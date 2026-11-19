const markerEnvironmentNames = [
  'implementation_name',
  'implementation_version',
  'os_name',
  'platform_machine',
  'platform_python_implementation',
  'platform_release',
  'platform_system',
  'platform_version',
  'python_full_version',
  'python_version',
  'sys_platform'
] as const;

export type PythonMarkerEnvironmentName =
  (typeof markerEnvironmentNames)[number];

export type PythonTargetProfile = Readonly<{
  id: string;
  environment: Readonly<Record<PythonMarkerEnvironmentName, string>>;
  extras: readonly string[];
}>;

type MarkerValue = Readonly<
  { kind: 'variable'; value: string } | { kind: 'literal'; value: string }
>;

type MarkerExpression = Readonly<
  | { kind: 'compare'; left: MarkerValue; operator: string; right: MarkerValue }
  | { kind: 'and'; left: MarkerExpression; right: MarkerExpression }
  | { kind: 'or'; left: MarkerExpression; right: MarkerExpression }
>;

type MarkerToken = Readonly<{
  kind: 'word' | 'string' | 'operator' | 'paren';
  value: string;
  start: number;
  end: number;
}>;

const markerVariables = new Set<string>([
  ...markerEnvironmentNames,
  'extra',
  'extras',
  'dependency_groups'
]);
const versionVariables = new Set([
  'implementation_version',
  'python_full_version',
  'python_version'
]);
const maximumMarkerBytes = 1_024;

export function parsePythonTargetProfile(value: unknown): PythonTargetProfile {
  if (!isRecord(value) || !onlyKeys(value, ['id', 'environment', 'extras']))
    throw new TypeError('Python target profile must be a JSON object.');
  if (
    typeof value.id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(value.id)
  )
    throw new TypeError('Python target profile ID is invalid.');
  const environment = value.environment;
  if (
    !isRecord(environment) ||
    Object.keys(environment).length !== markerEnvironmentNames.length ||
    markerEnvironmentNames.some(
      (name) =>
        typeof environment[name] !== 'string' ||
        environment[name].length === 0 ||
        environment[name].length > 256 ||
        /[\p{Cc}\0]/u.test(environment[name] as string)
    )
  )
    throw new TypeError(
      'Python target profile must define every marker environment value.'
    );
  const extras = value.extras ?? [];
  if (
    !Array.isArray(extras) ||
    extras.length > 64 ||
    extras.some(
      (extra) =>
        typeof extra !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(extra)
    )
  )
    throw new TypeError('Python target profile extras are invalid.');
  const copiedEnvironment = Object.create(null) as Record<
    PythonMarkerEnvironmentName,
    string
  >;
  for (const name of markerEnvironmentNames) {
    const entry = (environment as Record<string, unknown>)[name];
    if (typeof entry !== 'string')
      throw new TypeError(
        'Python target profile must define every marker environment value.'
      );
    copiedEnvironment[name] = entry;
  }
  return Object.freeze({
    id: value.id,
    environment: Object.freeze(copiedEnvironment),
    extras: Object.freeze([...new Set(extras.map(normalizePythonExtra))].sort())
  });
}

export function parsePythonTargetProfileJson(
  text: string
): PythonTargetProfile {
  if (
    Buffer.byteLength(text, 'utf8') === 0 ||
    Buffer.byteLength(text, 'utf8') > 4_096
  )
    throw new TypeError('Python target profile JSON exceeds 4 KiB.');
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new TypeError('Python target profile is not valid JSON.');
  }
  return parsePythonTargetProfile(value);
}

export function parsePythonMarkerExpression(
  source: string
): MarkerExpression | undefined {
  if (
    typeof source !== 'string' ||
    source.length === 0 ||
    Buffer.byteLength(source, 'utf8') > maximumMarkerBytes
  )
    return undefined;
  const tokens = tokenizeMarker(source);
  if (!tokens || tokens.length === 0) return undefined;
  let position = 0;
  const peek = (): MarkerToken | undefined => tokens[position];
  const take = (): MarkerToken | undefined => tokens[position++];
  const separated = (left: MarkerToken, right: MarkerToken): boolean =>
    /\s/u.test(source.slice(left.end, right.start));
  const parseValue = (): MarkerValue | undefined => {
    const token = take();
    if (token?.kind === 'string')
      return Object.freeze({ kind: 'literal', value: token.value });
    if (token?.kind === 'word' && markerVariables.has(token.value))
      return Object.freeze({ kind: 'variable', value: token.value });
    return undefined;
  };
  const parseOr = (depth: number): MarkerExpression | undefined => {
    if (depth > 32) return undefined;
    let left = parseAnd(depth);
    if (!left) return undefined;
    while (peek()?.kind === 'word' && peek()?.value === 'or') {
      const previous = tokens[position - 1];
      const operator = take();
      const next = peek();
      if (
        !previous ||
        !operator ||
        !next ||
        !separated(previous, operator) ||
        !separated(operator, next)
      )
        return undefined;
      const right = parseAnd(depth);
      if (!right) return undefined;
      left = Object.freeze({ kind: 'or', left, right });
    }
    return left;
  };
  const parseAnd = (depth: number): MarkerExpression | undefined => {
    if (depth > 32) return undefined;
    let left = parseAtom(depth);
    if (!left) return undefined;
    while (peek()?.kind === 'word' && peek()?.value === 'and') {
      const previous = tokens[position - 1];
      const operator = take();
      const next = peek();
      if (
        !previous ||
        !operator ||
        !next ||
        !separated(previous, operator) ||
        !separated(operator, next)
      )
        return undefined;
      const right = parseAtom(depth);
      if (!right) return undefined;
      left = Object.freeze({ kind: 'and', left, right });
    }
    return left;
  };
  const parseAtom = (depth: number): MarkerExpression | undefined => {
    if (depth > 32) return undefined;
    if (peek()?.kind === 'paren' && peek()?.value === '(') {
      take();
      const inner = parseOr(depth + 1);
      if (!inner || peek()?.kind !== 'paren' || peek()?.value !== ')')
        return undefined;
      take();
      return inner;
    }
    const left = parseValue();
    if (!left) return undefined;
    const operatorToken = peek();
    const inToken = tokens[position + 1];
    if (!operatorToken || position === 0) return undefined;
    const previous = tokens[position - 1];
    if (!previous || !separated(previous, operatorToken)) return undefined;
    let operator: string;
    if (operatorToken.kind === 'operator') {
      operator = operatorToken.value;
      take();
    } else if (
      operatorToken.kind === 'word' &&
      (operatorToken.value === 'in' ||
        (operatorToken.value === 'not' &&
          inToken?.kind === 'word' &&
          inToken.value === 'in' &&
          separated(operatorToken, inToken)))
    ) {
      operator = operatorToken.value === 'in' ? 'in' : 'not in';
      take();
      if (operator === 'not in') take();
    } else return undefined;
    const rightToken = tokens[position];
    const lastOperator = tokens[position - 1];
    const right = parseValue();
    if (
      !right ||
      !rightToken ||
      !lastOperator ||
      !separated(lastOperator, rightToken)
    )
      return undefined;
    return Object.freeze({ kind: 'compare', left, operator, right });
  };
  const expression = parseOr(0);
  return expression && position === tokens.length ? expression : undefined;
}

export function evaluatePythonMarkerExpression(
  source: string,
  profile: PythonTargetProfile,
  extraValues: readonly string[] = profile.extras
): boolean | undefined {
  if (
    extraValues.length > 64 ||
    extraValues.some((extra) => !validPythonExtra(extra))
  )
    return undefined;
  const expression = parsePythonMarkerExpression(source);
  if (!expression) return undefined;
  const extras = [...new Set(extraValues.map(normalizePythonExtra))];
  const selectedExtras = extras.length > 0 ? extras : [''];
  const evaluateForExtra = (extra: string): boolean | undefined => {
    const evaluate = (node: MarkerExpression): boolean | undefined => {
      if (node.kind === 'and') {
        const left = evaluate(node.left);
        if (left === false) return false;
        const right = evaluate(node.right);
        if (right === false) return false;
        return left === true && right === true ? true : undefined;
      }
      if (node.kind === 'or') {
        const left = evaluate(node.left);
        if (left === true) return true;
        const right = evaluate(node.right);
        if (right === true) return true;
        return left === false && right === false ? false : undefined;
      }
      const read = (value: MarkerValue): string | undefined => {
        if (value.kind === 'literal') return value.value;
        if (value.value === 'extra' || value.value === 'extras') return extra;
        if (value.value === 'dependency_groups') return undefined;
        return profile.environment[value.value as PythonMarkerEnvironmentName];
      };
      const left = read(node.left);
      const right = read(node.right);
      if (left === undefined || right === undefined) return undefined;
      if (node.operator === 'in') return right.includes(left);
      if (node.operator === 'not in') return !right.includes(left);
      if (
        node.left.kind === 'variable' &&
        versionVariables.has(node.left.value) &&
        node.right.kind === 'literal'
      )
        return comparePythonVersions(left, right, node.operator);
      switch (node.operator) {
        case '==':
        case '===':
          return left === right;
        case '!=':
          return left !== right;
        case '<':
          return left < right;
        case '<=':
          return left <= right;
        case '>':
          return left > right;
        case '>=':
          return left >= right;
        case '~=':
          return undefined;
        default:
          return undefined;
      }
    };
    return evaluate(expression);
  };
  const results = selectedExtras.map(evaluateForExtra);
  if (results.includes(true)) return true;
  return results.some((result) => result === undefined) ? undefined : false;
}

export function normalizePythonExtra(value: string): string {
  return value.toLowerCase().replace(/[-_.]+/gu, '-');
}

function validPythonExtra(value: string): boolean {
  return value === '' || /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value);
}

function tokenizeMarker(source: string): MarkerToken[] | undefined {
  const tokens: MarkerToken[] = [];
  for (let index = 0; index < source.length;) {
    const character = source[index] ?? '';
    if (/\s/u.test(character)) {
      index++;
      continue;
    }
    const start = index;
    if (character === '(' || character === ')') {
      index++;
      tokens.push({ kind: 'paren', value: character, start, end: index });
    } else if (character === "'" || character === '"') {
      const quote = character;
      let text = '';
      index++;
      let closed = false;
      while (index < source.length) {
        const current = source[index] ?? '';
        if (current === '\\') {
          const escaped = source[index + 1];
          if (escaped === undefined) return undefined;
          text += escaped;
          index += 2;
        } else if (current === quote) {
          index++;
          closed = true;
          break;
        } else if (current === '\n' || current === '\r' || current === '\0') {
          return undefined;
        } else {
          text += current;
          index++;
        }
      }
      if (!closed) return undefined;
      tokens.push({ kind: 'string', value: text, start, end: index });
    } else {
      const operator = /^(===|==|!=|<=|>=|~=|<|>)/u.exec(source.slice(index));
      if (operator?.[1]) {
        index += operator[1].length;
        tokens.push({
          kind: 'operator',
          value: operator[1],
          start,
          end: index
        });
      } else {
        const word = /^[A-Za-z_][A-Za-z0-9_]*/u.exec(source.slice(index));
        if (!word?.[0]) return undefined;
        index += word[0].length;
        tokens.push({
          kind: 'word',
          value: word[0].toLowerCase(),
          start,
          end: index
        });
      }
    }
    if (tokens.length > 256) return undefined;
  }
  return tokens;
}

type PythonVersion = Readonly<{
  epoch: number;
  release: readonly number[];
  pre: readonly [number, number] | null;
  post: number | null;
  dev: number | null;
  local: readonly (number | string)[];
}>;

function parsePythonVersion(value: string): PythonVersion | undefined {
  if (value.length > 128) return undefined;
  const match = value.match(
    /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:(?:[-_.]?)(alpha|a|beta|b|preview|pre|c|rc)(?:[-_.]?(\d+))?)?(?:-(\d+)|(?:[-_.]?post(?:[-_.]?(\d+))?))?(?:[-_.]?dev(?:[-_.]?(\d+))?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/iu
  );
  if (!match) return undefined;
  const release = (match[2] ?? '').split('.').map(Number);
  const epoch = Number(match[1] ?? 0);
  const preNumber = Number(match[4] ?? 0);
  const post = match[5] ?? match[6];
  const dev = match[7];
  if (
    release.length === 0 ||
    release.length > 16 ||
    release.some((part) => !Number.isSafeInteger(part)) ||
    !Number.isSafeInteger(epoch) ||
    !Number.isSafeInteger(preNumber) ||
    (post !== undefined && !Number.isSafeInteger(Number(post))) ||
    (dev !== undefined && !Number.isSafeInteger(Number(dev)))
  )
    return undefined;
  const preName = match[3]?.toLowerCase();
  const preRank = preName
    ? /^(?:a|alpha)$/u.test(preName)
      ? 0
      : /^(?:b|beta)$/u.test(preName)
        ? 1
        : 2
    : undefined;
  const local = match[8]
    ? match[8]
        .toLowerCase()
        .split(/[._-]/u)
        .map((part) => (/^\d+$/u.test(part) ? Number(part) : part))
    : [];
  if (
    local.some(
      (part) => typeof part === 'number' && !Number.isSafeInteger(part)
    )
  )
    return undefined;
  return Object.freeze({
    epoch,
    release: Object.freeze(release),
    pre:
      preRank === undefined
        ? null
        : Object.freeze([preRank, preNumber] as const),
    post: post === undefined ? null : Number(post),
    dev: dev === undefined ? null : Number(dev),
    local: Object.freeze(local)
  });
}

function compareTuple(
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

function comparePythonVersion(
  leftText: string,
  rightText: string,
  includeLocal = true
): number | undefined {
  const left = parsePythonVersion(leftText);
  const right = parsePythonVersion(rightText);
  if (!left || !right) return undefined;
  if (left.epoch !== right.epoch) return left.epoch < right.epoch ? -1 : 1;
  const release = compareTuple(left.release, right.release);
  if (release !== 0) return release;
  const preOrder = (version: PythonVersion): readonly [number, number] =>
    version.pre ??
    (version.dev !== null && version.post === null ? [-1, 0] : [3, 0]);
  const pre = compareTuple(preOrder(left), preOrder(right));
  if (pre !== 0) return pre;
  const post = compareOptionalNumber(left.post, right.post, -1, 1);
  if (post !== 0) return post;
  const dev = compareOptionalNumber(left.dev, right.dev, 1, -1);
  if (dev !== 0) return dev;
  const leftLocal = includeLocal ? left.local : [];
  const rightLocal = includeLocal ? right.local : [];
  const localLength = Math.max(leftLocal.length, rightLocal.length);
  for (let index = 0; index < localLength; index++) {
    const a = leftLocal[index];
    const b = rightLocal[index];
    if (a === undefined || b === undefined) {
      if (a !== b) return a === undefined ? -1 : 1;
      continue;
    }
    if (a === b) continue;
    if (typeof a === 'number' && typeof b === 'string') return 1;
    if (typeof a === 'string' && typeof b === 'number') return -1;
    return a < b ? -1 : 1;
  }
  return 0;
}

function compareOptionalNumber(
  left: number | null,
  right: number | null,
  leftMissing: number,
  rightMissing: number
): number {
  if (left === null && right === null) return 0;
  if (left === null) return leftMissing;
  if (right === null) return rightMissing;
  const a = left;
  const b = right;
  return a === b ? 0 : a < b ? -1 : 1;
}

function comparePythonVersions(
  left: string,
  right: string,
  operator: string
): boolean | undefined {
  if (operator === '===') return left === right;
  const wildcard = /^(\d+(?:\.\d+)*)\.\*$/u.exec(right);
  if (wildcard && (operator === '==' || operator === '!=')) {
    const prefix = wildcard[1] ?? '';
    const matches = left === prefix || left.startsWith(`${prefix}.`);
    return operator === '==' ? matches : !matches;
  }
  const comparison = comparePythonVersion(left, right);
  if (comparison === undefined) return undefined;
  switch (operator) {
    case '==':
      return comparison === 0;
    case '!=':
      return comparison !== 0;
    case '<':
      return comparison < 0;
    case '<=':
      return comparison <= 0;
    case '>':
      return comparison > 0;
    case '>=':
      return comparison >= 0;
    case '~=': {
      const requested = parsePythonVersion(right);
      const candidate = parsePythonVersion(left);
      if (!requested || !candidate || requested.release.length < 2)
        return undefined;
      const compatiblePrefix = requested.release.slice(0, -1);
      const upperRelease = [
        ...(compatiblePrefix.length > 0 ? compatiblePrefix.slice(0, -1) : []),
        (compatiblePrefix.at(-1) ?? requested.release[0] ?? 0) + 1
      ];
      const upper = `${requested.epoch ? `${requested.epoch}!` : ''}${upperRelease.join('.')}`;
      const lowerComparison = comparePythonVersion(left, right);
      const upperComparison = comparePythonVersion(left, upper);
      return lowerComparison !== undefined && upperComparison !== undefined
        ? lowerComparison >= 0 && upperComparison < 0
        : undefined;
    }
    case '===':
      return left === right;
    default:
      return undefined;
  }
}

export function pythonVersionSatisfies(
  version: string,
  requirement: string
): boolean | undefined {
  if (requirement.trim() === '' || requirement.trim() === '*')
    return parsePythonVersion(version.trim()) ? true : undefined;
  if (requirement.length > 2_048) return undefined;
  const candidate = parsePythonVersion(version.trim());
  if (!candidate) return undefined;
  const clauses = requirement.split(',');
  if (clauses.length === 0 || clauses.length > 32) return undefined;
  const allowsPrerelease = clauses.some((rawClause) => {
    const clause = rawClause.trim();
    const arbitrary = clause.startsWith('===');
    const match = arbitrary
      ? undefined
      : /^(?:~=|==|!=|>=|<=|>|<|=)?\s*(\S+)$/u.exec(clause);
    const expected = match?.[1]
      ? parsePythonVersion(match[1].replace(/\.\*$/u, ''))
      : arbitrary
        ? parsePythonVersion(clause.slice(3).trim())
        : undefined;
    return Boolean(
      expected && (expected.pre !== null || expected.dev !== null)
    );
  });
  if ((candidate.pre !== null || candidate.dev !== null) && !allowsPrerelease)
    return false;
  for (const rawClause of clauses) {
    const clause = rawClause.trim();
    if (!clause) return undefined;
    if (clause.startsWith('===')) {
      if (version.trim().toLowerCase() !== clause.slice(3).trim().toLowerCase())
        return false;
      continue;
    }
    const wildcard = /^(==|!=)\s*((?:\d+!)?\d+(?:\.\d+)*)\.\*$/u.exec(clause);
    if (wildcard?.[1] && wildcard[2]) {
      const prefix = parsePythonVersion(wildcard[2]);
      if (!prefix) return undefined;
      const matches =
        candidate.epoch === prefix.epoch &&
        prefix.release.every(
          (part, index) => (candidate.release[index] ?? 0) === part
        );
      if (
        (wildcard[1] === '==' && !matches) ||
        (wildcard[1] === '!=' && matches)
      )
        return false;
      continue;
    }
    const comparison = /^(~=|==|!=|>=|<=|>|<|=)?\s*(\S+)$/u.exec(clause);
    if (!comparison?.[2]) return undefined;
    const operator = comparison[1] === '=' ? '==' : (comparison[1] ?? '==');
    const expected = parsePythonVersion(comparison[2]);
    if (!expected) return undefined;
    if (
      ['<', '<=', '>', '>=', '~='].includes(operator) &&
      expected.local.length > 0
    )
      return undefined;
    const compareLocal =
      operator === '==' || operator === '!='
        ? expected.local.length > 0
        : false;
    const result = comparePythonVersion(version, comparison[2], compareLocal);
    if (result === undefined) return undefined;
    let matches: boolean;
    switch (operator) {
      case '==':
        matches = result === 0;
        break;
      case '!=':
        matches = result !== 0;
        break;
      case '<':
        matches = result < 0;
        break;
      case '<=':
        matches = result <= 0;
        break;
      case '>':
        matches = result > 0;
        break;
      case '>=':
        matches = result >= 0;
        break;
      case '~=': {
        if (expected.release.length < 2) return undefined;
        const prefix = expected.release.slice(0, -1);
        const upperRelease = [
          ...(prefix.length > 1 ? prefix.slice(0, -1) : []),
          (prefix.at(-1) ?? expected.release[0] ?? 0) + 1
        ];
        const upper = `${expected.epoch ? `${expected.epoch}!` : ''}${upperRelease.join('.')}`;
        const upperComparison = comparePythonVersion(version, upper, false);
        if (upperComparison === undefined) return undefined;
        matches = result >= 0 && upperComparison < 0;
        break;
      }
      default:
        return undefined;
    }
    if (!matches) return false;
  }
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]) {
  return Object.keys(value).every((key) => allowed.includes(key));
}
