const supportedGoos = new Set([
  'aix',
  'android',
  'darwin',
  'dragonfly',
  'freebsd',
  'illumos',
  'ios',
  'js',
  'linux',
  'netbsd',
  'openbsd',
  'plan9',
  'solaris',
  'wasip1',
  'windows'
]);
const supportedGoarch = new Set([
  '386',
  'amd64',
  'amd64p32',
  'arm',
  'arm64',
  'loong64',
  'mips',
  'mipsle',
  'mips64',
  'mips64le',
  'ppc64',
  'ppc64le',
  'riscv64',
  's390x',
  'sparc64',
  'wasm'
]);
const goReleaseTag = /^go1\.(\d+)$/u;
const maxGoConstraintBytes = 4_096;

export type GoTargetProfile = Readonly<{
  id: string;
  goos: string;
  goarch: string;
  cgo: boolean;
  goVersion?: string;
  tags: readonly string[];
}>;

type GoConstraint = Readonly<
  | { kind: 'tag'; value: string }
  | { kind: 'not'; value: GoConstraint }
  | { kind: 'and'; left: GoConstraint; right: GoConstraint }
  | { kind: 'or'; left: GoConstraint; right: GoConstraint }
>;

type Token = Readonly<{ kind: 'word' | 'operator' | 'paren'; value: string }>;

export function parseGoTargetProfile(value: unknown): GoTargetProfile {
  if (
    !record(value) ||
    !onlyKeys(value, ['id', 'goos', 'goarch', 'cgo', 'goVersion', 'tags'])
  )
    throw new TypeError('Go target profile must be a JSON object.');
  if (
    typeof value.id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(value.id) ||
    typeof value.goos !== 'string' ||
    !supportedGoos.has(value.goos) ||
    typeof value.goarch !== 'string' ||
    !supportedGoarch.has(value.goarch) ||
    typeof value.cgo !== 'boolean'
  )
    throw new TypeError('Go target profile identity is invalid.');
  if (
    value.goVersion !== undefined &&
    (typeof value.goVersion !== 'string' ||
      !/^1\.\d+(?:\.\d+)?$/u.test(value.goVersion) ||
      !value.goVersion
        .split('.')
        .every((part) => Number.isSafeInteger(Number(part))))
  )
    throw new TypeError('Go target profile version is invalid.');
  const tags = value.tags ?? [];
  if (
    !Array.isArray(tags) ||
    tags.length > 128 ||
    tags.some((tag) => typeof tag !== 'string' || !validGoTag(tag))
  )
    throw new TypeError('Go target profile build tags are invalid.');
  return Object.freeze({
    id: value.id,
    goos: value.goos,
    goarch: value.goarch,
    cgo: value.cgo,
    ...(typeof value.goVersion === 'string'
      ? { goVersion: value.goVersion }
      : {}),
    tags: Object.freeze([...new Set(tags as string[])].sort())
  });
}

export function parseGoTargetProfileJson(text: string): GoTargetProfile {
  if (
    Buffer.byteLength(text, 'utf8') === 0 ||
    Buffer.byteLength(text, 'utf8') > 4_096
  )
    throw new TypeError('Go target profile JSON exceeds 4 KiB.');
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new TypeError('Go target profile is not valid JSON.');
  }
  return parseGoTargetProfile(value);
}

export function goSourceFileMatchesTarget(
  relativePath: string,
  source: string,
  target?: GoTargetProfile
): boolean | undefined {
  // Go test files are compiled only by `go test`, never as part of the
  // application's dependency graph. Counting their imports as runtime edges
  // would make test-only packages appear installed for production builds.
  if (relativePath.endsWith('_test.go')) return false;
  const fileTags = filenameConstraints(relativePath);
  if (fileTags.length > 0) {
    if (!target) return undefined;
    if (
      fileTags.some(
        (tag) =>
          tag.kind === 'goos' &&
          evaluateGoConstraint({ kind: 'tag', value: tag.value }, target) !==
            true
      )
    )
      return false;
    if (
      fileTags.some(
        (tag) => tag.kind === 'goarch' && tag.value !== target.goarch
      )
    )
      return false;
  }
  const directives = leadingBuildDirectives(source);
  if (!directives.complete) return undefined;
  if (!directives.goBuild && directives.plusBuild.length === 0) return true;
  if (!target) return undefined;
  let goBuildState: boolean | undefined;
  if (directives.goBuild) {
    const parsed = parseGoBuildExpression(directives.goBuild);
    if (!parsed) return undefined;
    goBuildState = evaluateGoConstraint(parsed, target);
  }
  let plusBuildState: boolean | undefined;
  if (directives.plusBuild.length > 0) {
    const lineStates = directives.plusBuild.map((line) =>
      evaluatePlusBuildLine(line, target)
    );
    if (lineStates.some((state) => state === undefined)) return undefined;
    plusBuildState = lineStates.every((state) => state === true);
  }
  if (
    goBuildState !== undefined &&
    plusBuildState !== undefined &&
    goBuildState !== plusBuildState
  )
    return undefined;
  return goBuildState ?? plusBuildState;
}

function filenameConstraints(
  relativePath: string
): Array<{ kind: 'goos' | 'goarch'; value: string }> {
  if (!relativePath.endsWith('.go')) return [];
  const basename = relativePath.slice(relativePath.lastIndexOf('/') + 1, -3);
  const stem = basename.endsWith('_test')
    ? basename.slice(0, -'_test'.length)
    : basename;
  const parts = stem.split('_');
  const last = parts.at(-1) ?? '';
  const previous = parts.at(-2) ?? '';
  const constraints: Array<{ kind: 'goos' | 'goarch'; value: string }> = [];
  if (supportedGoos.has(previous) && supportedGoarch.has(last)) {
    constraints.push({ kind: 'goos', value: previous });
    constraints.push({ kind: 'goarch', value: last });
  } else if (supportedGoos.has(last)) {
    constraints.push({ kind: 'goos', value: last });
  } else if (supportedGoarch.has(last)) {
    constraints.push({ kind: 'goarch', value: last });
  }
  return constraints;
}

function leadingBuildDirectives(source: string): {
  complete: boolean;
  goBuild?: string;
  plusBuild: string[];
} {
  const lines = source.split(/\r?\n/u);
  const plusBuild: string[] = [];
  let goBuild: string | undefined;
  let sawCode = false;
  let directiveNeedsBlankLine = false;
  let inBlockComment = false;
  for (const line of lines.slice(0, 100)) {
    const trimmed = line.trim();
    if (inBlockComment) {
      if (trimmed.includes('*/')) inBlockComment = false;
      continue;
    }
    if (!trimmed) {
      directiveNeedsBlankLine = false;
      continue;
    }
    if (trimmed.startsWith('/*')) {
      if (!trimmed.includes('*/')) inBlockComment = true;
      continue;
    }
    if (trimmed.startsWith('//')) {
      const goBuildMatch = trimmed.match(/^\/\/\s*go:build\s+(.+)$/u);
      const plusMatch = trimmed.match(/^\/\/\s*\+build\s+(.+)$/u);
      if (goBuildMatch?.[1]) {
        if (goBuild !== undefined) return { complete: false, plusBuild };
        goBuild = goBuildMatch[1].trim();
        directiveNeedsBlankLine = true;
      }
      if (plusMatch?.[1]) {
        plusBuild.push(plusMatch[1].trim());
        directiveNeedsBlankLine = true;
      }
      continue;
    }
    if (directiveNeedsBlankLine) return { complete: false, plusBuild };
    sawCode = true;
    break;
  }
  if (inBlockComment || !sawCode) return { complete: false, plusBuild };
  return { complete: true, ...(goBuild ? { goBuild } : {}), plusBuild };
}

function parseGoBuildExpression(source: string): GoConstraint | undefined {
  if (
    source.length === 0 ||
    Buffer.byteLength(source, 'utf8') > maxGoConstraintBytes
  )
    return undefined;
  const tokens: Token[] = [];
  for (let index = 0; index < source.length;) {
    const char = source[index] ?? '';
    if (/\s/u.test(char)) {
      index++;
      continue;
    }
    if ('!()'.includes(char)) {
      tokens.push({
        kind: char === '(' || char === ')' ? 'paren' : 'operator',
        value: char
      });
      index++;
    } else if (
      source.startsWith('&&', index) ||
      source.startsWith('||', index)
    ) {
      const value = source.slice(index, index + 2);
      tokens.push({ kind: 'operator', value });
      index += 2;
    } else {
      const word = /^[A-Za-z0-9_][A-Za-z0-9_.-]*/u.exec(source.slice(index));
      if (!word?.[0] || !validGoTag(word[0])) return undefined;
      tokens.push({ kind: 'word', value: word[0] });
      index += word[0].length;
    }
    if (tokens.length > 512) return undefined;
  }
  let position = 0;
  const peek = (): Token | undefined => tokens[position];
  const take = (): Token | undefined => tokens[position++];
  const parseOr = (depth: number): GoConstraint | undefined => {
    if (depth > 64) return undefined;
    let left = parseAnd(depth);
    while (left && peek()?.value === '||') {
      take();
      const right = parseAnd(depth);
      if (!right) return undefined;
      left = { kind: 'or', left, right };
    }
    return left;
  };
  const parseAnd = (depth: number): GoConstraint | undefined => {
    let left = parseUnary(depth);
    while (left && peek()?.value === '&&') {
      take();
      const right = parseUnary(depth);
      if (!right) return undefined;
      left = { kind: 'and', left, right };
    }
    return left;
  };
  const parseUnary = (depth: number): GoConstraint | undefined => {
    if (depth > 64) return undefined;
    if (peek()?.value === '!') {
      take();
      const child = parseUnary(depth + 1);
      return child ? { kind: 'not', value: child } : undefined;
    }
    if (peek()?.value === '(') {
      take();
      const child = parseOr(depth + 1);
      if (!child || peek()?.value !== ')') return undefined;
      take();
      return child;
    }
    const token = take();
    return token?.kind === 'word'
      ? { kind: 'tag', value: token.value }
      : undefined;
  };
  const expression = parseOr(0);
  return expression && position === tokens.length ? expression : undefined;
}

function evaluateGoConstraint(
  expression: GoConstraint,
  target: GoTargetProfile
): boolean | undefined {
  if (expression.kind === 'not') {
    const value = evaluateGoConstraint(expression.value, target);
    return value === undefined ? undefined : !value;
  }
  if (expression.kind === 'and' || expression.kind === 'or') {
    const left = evaluateGoConstraint(expression.left, target);
    if (expression.kind === 'and' && left === false) return false;
    if (expression.kind === 'or' && left === true) return true;
    const right = evaluateGoConstraint(expression.right, target);
    if (expression.kind === 'and' && right === false) return false;
    if (expression.kind === 'or' && right === true) return true;
    return left === undefined || right === undefined
      ? undefined
      : expression.kind === 'and'
        ? left && right
        : left || right;
  }
  const tag = expression.value;
  const release = goReleaseTag.exec(tag);
  if (release) {
    if (!target.goVersion) return undefined;
    const current = Number(target.goVersion.split('.')[1]);
    const required = Number(release[1]);
    if (!Number.isSafeInteger(required)) return undefined;
    return required <= current;
  }
  const feature = goArchitectureFeature(tag);
  if (feature) {
    if (feature.arch !== target.goarch) return false;
    const selected = target.tags
      .map(goArchitectureFeature)
      .filter(
        (candidate): candidate is GoArchitectureFeature =>
          candidate?.arch === target.goarch
      );
    if (selected.length === 0) return undefined;
    const current = selected.find(
      (candidate) => candidate.value === feature.value
    );
    if (current) return true;
    if (feature.numeric && selected.some((candidate) => candidate.numeric)) {
      const currentVersion = selected
        .filter((candidate) => candidate.numeric)
        .flatMap((candidate) => (candidate.numeric ? [candidate.numeric] : []))
        .sort(compareNumberTuples)
        .at(-1);
      return currentVersion
        ? compareNumberTuples(currentVersion, feature.numeric) >= 0
        : undefined;
    }
    return undefined;
  }
  const tags = new Set<string>([
    ...target.tags,
    target.goos,
    target.goarch,
    ...(target.cgo ? ['cgo'] : [])
  ]);
  if (target.goos === 'android') tags.add('linux');
  if (target.goos === 'illumos') tags.add('solaris');
  if (target.goos === 'ios') tags.add('darwin');
  if (
    [
      'aix',
      'android',
      'darwin',
      'dragonfly',
      'freebsd',
      'illumos',
      'linux',
      'netbsd',
      'openbsd',
      'solaris'
    ].includes(target.goos)
  )
    tags.add('unix');
  return tags.has(tag);
}

function evaluatePlusBuildLine(
  line: string,
  target: GoTargetProfile
): boolean | undefined {
  const alternatives = line.split(/\s+/u);
  if (alternatives.some((item) => !item)) return undefined;
  let unknown = false;
  for (const alternative of alternatives) {
    const terms = alternative.split(',');
    if (
      terms.some(
        (term) => !validGoTag(term.startsWith('!') ? term.slice(1) : term)
      )
    )
      return undefined;
    let matches = true;
    for (const term of terms) {
      const negated = term.startsWith('!');
      const tag = negated ? term.slice(1) : term;
      const state = evaluateGoConstraint({ kind: 'tag', value: tag }, target);
      if (state === undefined) {
        unknown = true;
        matches = false;
        continue;
      }
      if ((negated && state) || (!negated && !state)) matches = false;
    }
    if (matches) return true;
  }
  return unknown ? undefined : false;
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

function onlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[]
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function validGoTag(value: string): boolean {
  return (
    /^go1\.\d+$/u.test(value) ||
    /^[A-Za-z_][A-Za-z0-9_]*$/u.test(value) ||
    /^goexperiment\.[A-Za-z_][A-Za-z0-9_]*$/u.test(value) ||
    goArchitectureFeature(value) !== undefined
  );
}

type GoArchitectureFeature = Readonly<{
  arch: string;
  value: string;
  numeric?: readonly number[];
}>;

function goArchitectureFeature(
  value: string
): GoArchitectureFeature | undefined {
  const separator = value.indexOf('.');
  if (separator < 0) return undefined;
  const arch = value.slice(0, separator);
  const feature = value.slice(separator + 1);
  if (
    !supportedGoarch.has(arch) ||
    !feature ||
    !/^[A-Za-z0-9_.]+$/u.test(feature)
  )
    return undefined;
  const numericText = feature.replace(/^v/u, '');
  const numericParts = numericText.split('.');
  const numeric = numericParts.every((part) => /^\d+$/u.test(part))
    ? numericParts.map(Number)
    : undefined;
  if (numeric?.some((part) => !Number.isSafeInteger(part))) return undefined;
  return Object.freeze({
    arch,
    value: feature,
    ...(numeric ? { numeric: Object.freeze(numeric) } : {})
  });
}

function compareNumberTuples(
  left: readonly number[],
  right: readonly number[]
): number {
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) {
    const a = left[index] ?? 0;
    const b = right[index] ?? 0;
    if (a !== b) return a < b ? -1 : 1;
  }
  return 0;
}
