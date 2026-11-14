import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import path from 'node:path';
import type { Finding, FindingSeverity } from '../../contracts/finding.js';
import { coverageOf } from '../../contracts/analysis.js';
import { createScannerContext } from '../../core/scanner-context.js';
import { bindSourceProvenance } from '../../core/source-provenance.js';
import {
  TextFileReader,
  type TextFileReadResult
} from '../../core/text-file-reader.js';
import type { ProjectFile } from '../../core/file-walker.js';
import type { ScannerContext } from '../../core/scanner-context.js';
import {
  snapshotContentProvider,
  type ProjectSnapshot
} from '../../application/project-snapshot.js';

type DockerfileReader = Pick<TextFileReader, 'read' | 'usage'>;

type DockerRule = {
  id: string;
  title: string;
  severity: FindingSeverity;
  test: (line: string, allLines: string[]) => boolean;
  message: string;
  remediation: string;
};

function isRootUser(value: string): boolean {
  const identity = value.trim().split(/\s/u)[0]?.split(':', 1)[0] ?? '';
  if (identity.toLowerCase() === 'root') return true;
  if (!/^\d+$/u.test(identity)) return false;
  try {
    return BigInt(identity) === 0n;
  } catch {
    return false;
  }
}

function hasVerifiableUserIdentity(value: string): boolean {
  const identity = value.trim().split(/\s/u)[0]?.split(':', 1)[0] ?? '';
  return identity.toLowerCase() === 'root' || /^\d+$/u.test(identity);
}

function isSecretName(value: string): boolean {
  return /(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|PRIVATE[_-]?KEY)/iu.test(value);
}

function unquoteLiteral(value: string): string {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")))
  )
    return trimmed.slice(1, -1);
  return trimmed;
}

function isRemoteAddInstruction(line: string): boolean {
  const match = line.trim().match(/^ADD\s+(.+)$/isu);
  const rawArgument = match?.[1]?.trim();
  if (!rawArgument) return false;
  const argument = rawArgument.replace(/^(?:--[^\s]+\s+)+/u, '').trim();
  if (!argument) return false;
  if (argument.startsWith('[')) {
    try {
      const parsed: unknown = JSON.parse(argument);
      return (
        Array.isArray(parsed) &&
        parsed
          .slice(0, -1)
          .some(
            (source) =>
              typeof source === 'string' && /^https?:\/\//iu.test(source)
          )
      );
    } catch {
      return false;
    }
  }
  return /^(?:"|')?https?:\/\//iu.test(argument);
}

function declaresLiteralSecret(line: string): boolean {
  const match = line.trim().match(/^(ARG|ENV)\s+(.+)$/iu);
  if (!match?.[1] || !match[2]) return false;
  const command = match[1].toUpperCase();
  const content = match[2].trim();
  if (command === 'ARG') {
    const declaration = content.match(/^([A-Za-z_][\w-]*)(?:=(.*))?$/u);
    return Boolean(
      declaration?.[1] &&
      isSecretName(declaration[1]) &&
      unquoteLiteral(declaration[2] ?? '').length > 0
    );
  }

  const assignments = [
    ...content.matchAll(
      /(?:^|\s)([A-Za-z_][\w-]*)=("[^"\n]*"|'[^'\n]*'|[^\s]+)/gu
    )
  ];
  if (
    assignments.some(
      (assignment) =>
        isSecretName(assignment[1] ?? '') &&
        unquoteLiteral(assignment[2] ?? '').length > 0
    )
  )
    return true;
  const legacy = content.match(/^([A-Za-z_][\w-]*)\s+(.+)$/u);
  return Boolean(
    legacy?.[1] &&
    isSecretName(legacy[1]) &&
    unquoteLiteral(legacy[2] ?? '').length > 0
  );
}

const rules: DockerRule[] = [
  {
    id: 'TLP-DOCKER-001',
    title: 'Container may run as root',
    severity: 'high',
    test: (line) => isRootUser(line),
    message: 'The final stage may run as root.',
    remediation:
      'Create and switch to a dedicated non-root user before the final command.'
  },
  {
    id: 'TLP-DOCKER-002',
    title: 'Secret-like value in Docker ARG or ENV',
    severity: 'critical',
    test: declaresLiteralSecret,
    message: 'A secret-like variable is declared through ARG or ENV.',
    remediation:
      'Use runtime secret injection or BuildKit secret mounts instead of image metadata.'
  },
  {
    id: 'TLP-DOCKER-003',
    title: 'Unpinned base image tag',
    severity: 'medium',
    test: (line) => {
      const image = line
        .trim()
        .match(
          /^FROM\s+(?:(?:--platform=\S+|--platform\s+\S+)\s+)?(\S+)/iu
        )?.[1];
      return Boolean(image && !/^[^@\s]+@sha256:[a-f\d]{64}$/iu.test(image));
    },
    message: 'The base image is not pinned by digest.',
    remediation:
      'Pin trusted base images by immutable digest and review updates deliberately.'
  },
  {
    id: 'TLP-DOCKER-004',
    title: 'Remote ADD instruction',
    severity: 'high',
    test: isRemoteAddInstruction,
    message: 'ADD downloads remote content during the image build.',
    remediation:
      'Download explicitly, verify checksums, and use COPY for local content.'
  },
  {
    id: 'TLP-DOCKER-005',
    title: 'Package installation without cleanup',
    severity: 'low',
    test: (line) =>
      /apt-get\s+install/i.test(line) &&
      !/rm\s+-rf\s+\/var\/lib\/apt\/lists/i.test(line),
    message: 'apt package metadata may remain in the image layer.',
    remediation: 'Combine installation and cleanup in the same RUN instruction.'
  },
  {
    id: 'TLP-DOCKER-006',
    title: 'Final container stage has no active health check instruction',
    severity: 'low',
    test: (_line, lines) => {
      const lastHealthCheck = lines
        .filter((line) => /^HEALTHCHECK\s+/iu.test(line.trim()))
        .at(-1);
      return (
        !lastHealthCheck ||
        /^HEALTHCHECK\s+NONE(?:\s|$)/iu.test(lastHealthCheck.trim())
      );
    },
    message: 'No active HEALTHCHECK could be verified for the final stage.',
    remediation:
      'Add a HEALTHCHECK when the runtime can report meaningful service health.'
  },
  {
    id: 'TLP-DOCKER-007',
    title: 'Remote content is executed during the image build',
    severity: 'high',
    test: (line) => {
      const normalized = line.replace(/\s+/gu, ' ').trim();
      return (
        /^RUN\s+/iu.test(normalized) &&
        /(?:curl|wget)\b[^;&|]{0,300}(?:\||&&|;)[ \t]*(?:sh|bash|ash)\b/iu.test(
          normalized
        )
      );
    },
    message:
      'The build downloads and executes remote content without a pinned, independently verified artifact.',
    remediation:
      'Fetch a pinned artifact, verify its digest or signature, and execute it only after verification.'
  }
];

const remoteCopyRule: DockerRule = {
  id: 'TLP-DOCKER-008',
  title: 'Unpinned external image used as COPY source',
  severity: 'medium',
  test: () => false,
  message:
    'COPY imports bytes from an external image without a verified digest pin.',
  remediation:
    'Use COPY --from with an immutable image digest or a verified earlier stage.'
};

/** Creates the canonical finding for one Dockerfile rule match. */
function finding(
  rule: DockerRule,
  relativePath: string,
  lineNumber: number,
  confidence: Finding['confidence'] = 'high'
): Finding {
  return {
    id: `${rule.id}:${relativePath}:${lineNumber}`,
    ruleId: rule.id,
    title: rule.title,
    category: 'container',
    severity: rule.severity,
    confidence,
    message: rule.message,
    source: 'dockerfile',
    location: {
      file: relativePath,
      line: lineNumber,
      column: 1
    },
    evidence: [
      {
        // Dockerfile instructions often contain credentials in values that
        // cannot be identified reliably by a name-based redactor. Keep only
        // the rule identity and source location in normal evidence.
        summary: `Dockerfile content redacted (${rule.id}).`,
        fingerprint: `${relativePath}:${lineNumber}:${rule.id}`
      }
    ],
    remediation: {
      summary: rule.remediation
    }
  };
}

type DockerInstruction = { line: number; text: string };
type DockerExpansionBudget = { remainingBytes: number; exceeded: boolean };
const MAX_DOCKER_EXPANSION_BYTES = 8 * 1024 * 1024;

const builtinBuildArgs = new Set([
  'BUILDPLATFORM',
  'BUILDOS',
  'BUILDARCH',
  'BUILDVARIANT',
  'TARGETPLATFORM',
  'TARGETOS',
  'TARGETARCH',
  'TARGETVARIANT'
]);

type ResolvedFromImage = {
  line: string;
  image: string;
  alias?: string;
  unresolved: boolean;
};

function globalDockerArgs(
  instructions: readonly DockerInstruction[],
  escapeChar: string,
  budget: DockerExpansionBudget
): Map<string, string | undefined> {
  const values = new Map<string, string | undefined>();
  for (const instruction of instructions) {
    if (/^FROM\s+/iu.test(instruction.text)) break;
    const declaration = instruction.text.match(
      /^ARG\s+([A-Za-z_][\w]*)(?:=(.*))?$/iu
    );
    if (!declaration?.[1]) continue;
    const value = declaration[2];
    const expanded =
      value === undefined
        ? undefined
        : expandBuildArgs(value, values, escapeChar, budget);
    values.set(
      declaration[1],
      expanded === undefined || expanded.unresolved ? undefined : expanded.value
    );
  }
  return values;
}

function expandBuildArgs(
  source: string,
  values: ReadonlyMap<string, string | undefined>,
  escapeChar: string,
  budget: DockerExpansionBudget
): { value: string; unresolved: boolean } {
  if (budget.exceeded) return { value: '', unresolved: true };
  let unresolved = false;
  const pattern =
    /\$\{([A-Za-z_][\w]*)(?:(:-|:\+|-|\+)([^}]*))?\}|\$([A-Za-z_][\w]*)/gu;
  let cursor = 0;
  const expandedParts: string[] = [];
  const append = (part: string): boolean => {
    const bytes = Buffer.byteLength(part);
    if (bytes > budget.remainingBytes) {
      budget.exceeded = true;
      expandedParts.length = 0;
      return false;
    }
    budget.remainingBytes -= bytes;
    expandedParts.push(part);
    return true;
  };
  for (const match of source.matchAll(pattern)) {
    const token = match[0];
    const index = match.index;
    if (index === undefined) continue;
    if (!append(source.slice(cursor, index)))
      return { value: '', unresolved: true };
    let escapedCount = 0;
    for (
      let escapeIndex = index - 1;
      escapeIndex >= 0 && source[escapeIndex] === escapeChar;
      escapeIndex--
    )
      escapedCount++;
    if (escapedCount % 2 === 1) {
      unresolved = true;
      const escapedName = match[1] ?? match[4] ?? '';
      if (!append(`__TOOLIP_ESCAPED_${escapedName}__`))
        return { value: '', unresolved: true };
      cursor = index + token.length;
      continue;
    }
    const name = match[1] ?? match[4] ?? '';
    const operator = match[2];
    const fallback = match[3];
    if (builtinBuildArgs.has(name)) {
      unresolved = true;
      if (!append(`__TOOLIP_BUILTIN_${name}__`))
        return { value: '', unresolved: true };
    } else {
      const resolved = values.get(name);
      let replacement: string;
      if (operator === ':-')
        replacement =
          resolved !== undefined && resolved !== ''
            ? resolved
            : (fallback ?? '');
      else if (operator === '-') replacement = resolved ?? fallback ?? '';
      else if (operator === ':+')
        replacement =
          resolved !== undefined && resolved !== '' ? (fallback ?? '') : '';
      else if (operator === '+')
        replacement = resolved !== undefined ? (fallback ?? '') : '';
      else if (resolved !== undefined) replacement = resolved;
      else {
        unresolved = true;
        replacement = `__TOOLIP_UNKNOWN_${name}__`;
      }
      if (!append(replacement)) return { value: '', unresolved: true };
    }
    cursor = index + token.length;
  }
  if (!append(source.slice(cursor))) return { value: '', unresolved: true };
  const value = expandedParts.join('');
  if (value.includes('$')) unresolved = true;
  return { value, unresolved };
}

function resolveFromImage(
  instruction: DockerInstruction,
  buildArgs: ReadonlyMap<string, string | undefined>,
  escapeChar: string,
  budget: DockerExpansionBudget
): ResolvedFromImage | undefined {
  const match = instruction.text.match(/^FROM\s+(.+)$/iu);
  if (!match?.[1]) return undefined;
  const tokens = match[1].trim().split(/\s+/u);
  let imageIndex = 0;
  let seenPlatform = false;
  let platformUnknown = false;
  while (tokens[imageIndex]?.startsWith('--')) {
    const option = tokens[imageIndex] ?? '';
    if (option.startsWith('--platform=')) {
      if (seenPlatform || !option.slice('--platform='.length)) return undefined;
      seenPlatform = true;
      const rawPlatform = option.slice('--platform='.length);
      platformUnknown ||=
        rawPlatform.includes('$') ||
        expandBuildArgs(rawPlatform, buildArgs, escapeChar, budget).unresolved;
      imageIndex += 1;
    } else if (option === '--platform') {
      if (
        seenPlatform ||
        !tokens[imageIndex + 1] ||
        tokens[imageIndex + 1]?.startsWith('--')
      )
        return undefined;
      seenPlatform = true;
      const rawPlatform = tokens[imageIndex + 1] ?? '';
      platformUnknown ||=
        rawPlatform.includes('$') ||
        expandBuildArgs(rawPlatform, buildArgs, escapeChar, budget).unresolved;
      imageIndex += 2;
    } else return undefined;
  }
  if (imageIndex >= tokens.length) return undefined;
  const imageToken = tokens[imageIndex] ?? '';
  const aliasKeyword = tokens[imageIndex + 1];
  const alias = tokens[imageIndex + 2];
  const hasAlias = aliasKeyword?.toUpperCase() === 'AS';
  if (
    !imageToken ||
    (aliasKeyword !== undefined && !hasAlias) ||
    (hasAlias && (!alias || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(alias))) ||
    tokens.length - imageIndex > (hasAlias ? 3 : 1)
  )
    return undefined;
  const imageExpression = tokens[imageIndex] ?? '';
  const expanded = expandBuildArgs(
    imageExpression,
    buildArgs,
    escapeChar,
    budget
  );
  tokens[imageIndex] = expanded.value;
  return {
    line: `FROM ${tokens.join(' ')}`,
    image: expanded.value,
    ...(hasAlias && alias ? { alias } : {}),
    unresolved:
      expanded.unresolved || imageExpression.includes('$') || platformUnknown
  };
}

function parseInstructions(source: string): {
  instructions: DockerInstruction[];
  warnings: string[];
  escapeChar: string;
} {
  const physical = source.split(/\r?\n/u);
  const warnings: string[] = [];
  // Only leading parser directives affect the frontend or escape rules. Blank
  // lines, ordinary comments and instructions terminate the directive prefix.
  let escapeDirective: string | undefined;
  let syntaxDirective: string | undefined;
  let directivePrefixLength = 0;
  for (const line of physical) {
    const directive = line.match(/^\s*#\s*(syntax|escape|check)=/iu);
    if (!directive) break;
    directivePrefixLength++;
    const directiveName = directive[1]?.toLowerCase();
    if (directiveName === 'syntax') {
      if (syntaxDirective !== undefined) {
        warnings.push(
          `${directivePrefixLength}: duplicate Dockerfile syntax directive; frontend semantics are unknown`
        );
        continue;
      }
      syntaxDirective = line;
      continue;
    }
    if (directiveName !== 'escape') continue;
    if (escapeDirective !== undefined) {
      warnings.push(
        `${directivePrefixLength}: duplicate Dockerfile escape directive; syntax semantics are unknown`
      );
      continue;
    }
    escapeDirective = line;
  }
  const escapeLine = escapeDirective?.match(/^\s*#\s*escape=([`\\])\s*$/iu);
  if (escapeDirective && !escapeLine)
    warnings.push(
      `${physical.indexOf(escapeDirective) + 1}: invalid Dockerfile escape directive; default escape semantics were used`
    );
  const syntaxLine = syntaxDirective?.match(/^\s*#\s*syntax=([^\s]+)\s*$/iu);
  if (
    syntaxDirective &&
    (!syntaxLine?.[1] ||
      !/^docker\/dockerfile:1(?:\.\d+)?(?:@sha256:[a-f\d]{64})?$/iu.test(
        syntaxLine[1]
      ))
  )
    warnings.push(
      `${physical.indexOf(syntaxDirective) + 1}: custom or invalid Dockerfile frontend; instruction semantics are unknown`
    );
  const escapeChar = escapeLine?.[1] ?? '\\';
  const instructions: DockerInstruction[] = [];
  const supportedCommands = new Set([
    'ADD',
    'ARG',
    'CMD',
    'COPY',
    'ENTRYPOINT',
    'ENV',
    'EXPOSE',
    'FROM',
    'HEALTHCHECK',
    'LABEL',
    'MAINTAINER',
    'ONBUILD',
    'RUN',
    'SHELL',
    'STOPSIGNAL',
    'USER',
    'VOLUME',
    'WORKDIR'
  ]);
  let bufferParts: string[] = [];
  let startLine = 1;
  let continuing = false;

  const flush = (index: number): number => {
    const bufferedText = bufferParts.join(' ');
    if (!/^\s*[A-Za-z]+(?:\s+|$)/u.test(bufferedText)) {
      bufferParts = [];
      continuing = false;
      return index;
    }
    const instruction: DockerInstruction = {
      line: startLine,
      text: bufferedText
    };
    const command = bufferedText.match(/^\s*([A-Za-z]+)/u)?.[1]?.toUpperCase();
    if (command && !supportedCommands.has(command))
      warnings.push(
        `${startLine}: unsupported Dockerfile instruction; semantics are unknown`
      );
    if (command === 'ADD') {
      const argument = bufferedText
        .replace(/^\s*ADD\s+/iu, '')
        .replace(/^(?:--[^\s]+\s+)+/u, '')
        .trim();
      if (argument.startsWith('[')) {
        let validJsonForm = false;
        try {
          const parsed: unknown = JSON.parse(argument);
          validJsonForm =
            Array.isArray(parsed) &&
            parsed.length >= 2 &&
            parsed.every((value) => typeof value === 'string');
        } catch {
          validJsonForm = false;
        }
        if (!validJsonForm)
          warnings.push(
            `${startLine}: ADD JSON form is malformed or unsupported; source semantics are unknown`
          );
      }
    }
    const heredocs = ['RUN', 'COPY', 'ADD'].includes(command ?? '')
      ? [
          ...bufferedText.matchAll(
            /<<(-?)\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_]+))/gu
          )
        ].map((match) => ({
          delimiter: match[2] ?? match[3] ?? match[4] ?? '',
          stripTabs: Boolean(match[1])
        }))
      : [];
    const heredocOperators = ['RUN', 'COPY', 'ADD'].includes(command ?? '')
      ? (bufferedText.match(/<</gu) ?? []).length
      : 0;
    if (heredocOperators > heredocs.length)
      warnings.push(
        `${startLine}: unsupported or malformed Dockerfile heredoc marker; instruction semantics are unknown`
      );
    const body: string[] = [];
    let consumed = index;
    for (const heredoc of heredocs) {
      let terminated = false;
      while (consumed + 1 < physical.length) {
        consumed += 1;
        const line = physical[consumed] ?? '';
        const terminator = heredoc.stripTabs ? line.replace(/^\t+/u, '') : line;
        if (terminator === heredoc.delimiter) {
          terminated = true;
          break;
        }
        if (command === 'RUN') body.push(line);
      }
      if (!terminated)
        warnings.push(
          `${startLine}: unterminated Dockerfile heredoc; instruction semantics are unknown`
        );
    }
    if (command === 'RUN' && body.length > 0)
      instruction.text = `${instruction.text}\n${body.join('\n')}`;
    instructions.push(instruction);
    bufferParts = [];
    continuing = false;
    return consumed;
  };

  for (let index = 0; index < physical.length; index += 1) {
    const original = physical[index] ?? '';
    const lineNumber = index + 1;
    const line = original.trimEnd();
    if (!line.trim()) continue;
    if (/^\s*#/u.test(line)) {
      if (index >= directivePrefixLength && /^\s*#\s*escape=/iu.test(line))
        warnings.push(
          `${lineNumber}: late parser escape directive ignored; Dockerfile semantics require review`
        );
      continue;
    }
    if (bufferParts.length === 0) startLine = lineNumber;

    let trailingEscapes = 0;
    for (
      let cursor = line.length - 1;
      cursor >= 0 && line[cursor] === escapeChar;
      cursor--
    ) {
      trailingEscapes++;
    }
    const continued = trailingEscapes % 2 === 1;
    const fragment = continued ? line.slice(0, -1).trim() : line.trim();
    bufferParts.push(fragment);
    continuing = continued;
    if (continued) continue;
    index = flush(index);
  }
  if (bufferParts.length > 0) {
    if (continuing)
      warnings.push(
        `${startLine}: unterminated Dockerfile line continuation; instruction semantics are unknown`
      );
    flush(physical.length - 1);
  }
  return { instructions, warnings, escapeChar };
}

type DockerStage = {
  from: DockerInstruction;
  image: string;
  alias?: string;
  baseStage?: number;
  baseKind: 'stage' | 'scratch' | 'external' | 'unknown';
  instructions: DockerInstruction[];
  onBuildUnknown: boolean;
};

type DockerStageState = {
  user?: string;
  userKnown: boolean;
  userUnknownReason?: 'variable' | 'name' | 'syntax';
  userLine?: number;
  healthCheck?: 'active' | 'none';
  healthCheckKnown: boolean;
  healthCheckLine?: number;
};

type DockerStageGraph = {
  stages: DockerStage[];
  states: DockerStageState[];
  baseKindByFrom: Map<DockerInstruction, DockerStage['baseKind']>;
  resolvedFromByInstruction: Map<
    DockerInstruction,
    ResolvedFromImage | undefined
  >;
  remoteCopyLines: number[];
  warnings: string[];
};

function buildDockerStageGraph(
  instructions: readonly DockerInstruction[],
  buildArgs: ReadonlyMap<string, string | undefined>,
  escapeChar: string,
  budget: DockerExpansionBudget
): DockerStageGraph {
  const stages: DockerStage[] = [];
  const aliases = new Map<string, number>();
  const ambiguousAliases = new Set<string>();
  const baseKindByFrom = new Map<DockerInstruction, DockerStage['baseKind']>();
  const resolvedFromByInstruction = new Map<
    DockerInstruction,
    ResolvedFromImage | undefined
  >();
  const warnings: string[] = [];
  let current: DockerStage | undefined;

  for (const instruction of instructions) {
    if (!/^FROM\s+/iu.test(instruction.text)) {
      if (current) current.instructions.push(instruction);
      else if (!/^ARG\s+/iu.test(instruction.text))
        warnings.push(
          `${instruction.line}: instruction appears before the first FROM; stage semantics are unknown`
        );
      continue;
    }
    const parsed = resolveFromImage(instruction, buildArgs, escapeChar, budget);
    resolvedFromByInstruction.set(instruction, parsed);
    if (!parsed) {
      warnings.push(
        `${instruction.line}: FROM instruction could not be parsed; stage metadata is unknown`
      );
      current = {
        from: instruction,
        image: '',
        baseKind: 'unknown',
        instructions: [],
        onBuildUnknown: false
      };
      stages.push(current);
      baseKindByFrom.set(instruction, 'unknown');
      continue;
    }

    const image = parsed.image;
    const stageIndex = stages.length;
    let baseKind: DockerStage['baseKind'] = 'external';
    let baseStage: number | undefined;
    if (parsed.unresolved) {
      baseKind = 'unknown';
      warnings.push(
        `${instruction.line}: base image uses an unresolved build argument; digest pinning could not be verified`
      );
    } else if (image.toLowerCase() === 'scratch') {
      baseKind = 'scratch';
    } else if (/^\d+$/u.test(image)) {
      const numericIndex = Number(image);
      if (Number.isSafeInteger(numericIndex) && numericIndex < stageIndex) {
        baseKind = 'stage';
        baseStage = numericIndex;
      } else {
        baseKind = 'unknown';
        warnings.push(
          `${instruction.line}: FROM references an invalid prior stage index; inherited metadata is unknown`
        );
      }
    } else {
      const key = image.toLowerCase();
      const resolvedStage = aliases.get(key);
      if (resolvedStage !== undefined) {
        baseKind = 'stage';
        baseStage = resolvedStage;
      } else if (ambiguousAliases.has(key)) {
        baseKind = 'unknown';
        warnings.push(
          `${instruction.line}: FROM uses an ambiguous stage alias; inherited metadata is unknown`
        );
      }
    }

    const stage: DockerStage = {
      from: instruction,
      image,
      ...(parsed.alias ? { alias: parsed.alias } : {}),
      ...(baseStage !== undefined ? { baseStage } : {}),
      baseKind,
      instructions: [],
      onBuildUnknown: false
    };
    stages.push(stage);
    baseKindByFrom.set(instruction, baseKind);
    current = stage;
    if (parsed.alias) {
      const key = parsed.alias.toLowerCase();
      if (aliases.has(key) || ambiguousAliases.has(key)) {
        aliases.delete(key);
        ambiguousAliases.add(key);
        warnings.push(
          `${instruction.line}: duplicate stage alias is ambiguous`
        );
      } else aliases.set(key, stageIndex);
    }
  }

  for (const stage of stages) {
    const onBuild = stage.instructions.find((instruction) =>
      /^ONBUILD\s+/iu.test(instruction.text)
    );
    if (onBuild) {
      stage.onBuildUnknown = true;
      warnings.push(
        `${onBuild.line}: ONBUILD instruction effects are not evaluated; derived stage metadata may be unknown`
      );
    }
  }

  const states: DockerStageState[] = [];
  for (const stage of stages) {
    const inherited =
      stage.baseStage === undefined ? undefined : states[stage.baseStage];
    let state: DockerStageState = inherited
      ? { ...inherited }
      : stage.baseKind === 'scratch'
        ? {
            user: '0',
            userKnown: true,
            healthCheck: 'none',
            healthCheckKnown: true
          }
        : {
            userKnown: false,
            healthCheckKnown: false
          };
    if (
      inherited &&
      stage.baseStage !== undefined &&
      stages[stage.baseStage]?.onBuildUnknown
    ) {
      state = {
        ...state,
        user: undefined,
        userKnown: false,
        userUnknownReason: undefined,
        userLine: undefined,
        healthCheck: undefined,
        healthCheckKnown: false,
        healthCheckLine: undefined
      };
    }
    for (const instruction of stage.instructions) {
      const user = instruction.text.match(/^USER\s+(.+)$/iu)?.[1]?.trim();
      if (user !== undefined) {
        const identity = user.split(/\s/u)[0] ?? '';
        const unresolved = identity.includes('$');
        const syntaxValid = /^\S+$/u.test(user);
        const known = syntaxValid && hasVerifiableUserIdentity(identity);
        state = {
          ...state,
          user: known ? identity : undefined,
          userKnown: known,
          ...(!known
            ? {
                userUnknownReason: !syntaxValid
                  ? 'syntax'
                  : unresolved
                    ? 'variable'
                    : 'name'
              }
            : { userUnknownReason: undefined }),
          userLine: instruction.line
        };
      } else if (/^USER(?:\s|$)/iu.test(instruction.text)) {
        state = {
          ...state,
          user: undefined,
          userKnown: false,
          userUnknownReason: 'syntax',
          userLine: instruction.line
        };
      }
      const health = instruction.text.match(/^HEALTHCHECK\s+(.+)$/iu)?.[1];
      if (health !== undefined) {
        const healthTokens = health.trim().split(/\s+/u);
        let cursor = 0;
        let healthSyntaxValid = true;
        while (healthTokens[cursor]?.startsWith('--')) {
          const option = healthTokens[cursor] ?? '';
          const optionName = option.split('=', 1)[0];
          if (
            ![
              '--interval',
              '--timeout',
              '--start-period',
              '--start-interval',
              '--retries'
            ].includes(optionName ?? '')
          ) {
            healthSyntaxValid = false;
            break;
          }
          if (option.includes('=')) {
            if (!option.split('=').slice(1).join('='))
              healthSyntaxValid = false;
            cursor += 1;
          } else if (healthTokens[cursor + 1]) cursor += 2;
          else {
            healthSyntaxValid = false;
            break;
          }
        }
        const healthCommand = healthTokens[cursor]?.toUpperCase();
        const isNone =
          cursor === 0 && healthCommand === 'NONE' && healthTokens.length === 1;
        const isCommand =
          healthCommand === 'CMD' && cursor + 1 < healthTokens.length;
        if (!healthSyntaxValid || (!isNone && !isCommand)) {
          warnings.push(
            `${instruction.line}: HEALTHCHECK syntax is unsupported; active state is unknown`
          );
          state = { ...state, healthCheck: undefined, healthCheckKnown: false };
          continue;
        }
        state = {
          ...state,
          healthCheck: isNone ? 'none' : 'active',
          healthCheckKnown: true,
          healthCheckLine: instruction.line
        };
      } else if (/^HEALTHCHECK(?:\s|$)/iu.test(instruction.text)) {
        state = { ...state, healthCheckKnown: false };
        warnings.push(
          `${instruction.line}: HEALTHCHECK syntax is unsupported; active state is unknown`
        );
      }
    }
    states.push(state);
  }

  const remoteCopyLines: number[] = [];
  for (let index = 0; index < stages.length; index++) {
    const stage = stages[index];
    if (!stage) continue;
    for (const instruction of stage.instructions) {
      if (!/^COPY(?:\s|$)/iu.test(instruction.text)) continue;
      const argument = instruction.text.replace(/^COPY\s+/iu, '');
      const from = /(?:^|\s)--from=(\S+)/u.exec(argument)?.[1];
      if (from === undefined) {
        if (/(?:^|\s)--from(?:\s|$|=)/u.test(argument))
          warnings.push(
            instruction.line +
              ': malformed COPY --from option; source identity is unknown'
          );
        continue;
      }
      // Only an already-declared stage alias or backwards numeric index
      // is an internal source; later stages cannot be addressed.
      if (
        from.includes('$') ||
        from.includes('\\') ||
        from.includes(String.fromCharCode(96)) ||
        from.includes('__TOOLIP_')
      ) {
        warnings.push(
          instruction.line +
            ': COPY --from variable or escape is unresolved; source provenance is unknown'
        );
        continue;
      }
      if (/^\d+$/u.test(from)) {
        const stageNumber = Number(from);
        if (Number.isSafeInteger(stageNumber) && stageNumber < index) continue;
        warnings.push(
          instruction.line +
            ': COPY --from references a future/invalid stage index'
        );
        continue;
      }
      const alias = aliases.get(from.toLowerCase());
      if (alias !== undefined && alias < index) continue;
      if (alias !== undefined || ambiguousAliases.has(from.toLowerCase())) {
        warnings.push(
          instruction.line + ': COPY --from stage alias is future or ambiguous'
        );
        continue;
      }
      if (
        !/^[A-Za-z0-9][A-Za-z0-9._/:-]*(?:@sha256:[a-f0-9]{64})?$/iu.test(from)
      ) {
        warnings.push(
          instruction.line +
            ': COPY --from external image syntax is unsupported'
        );
        continue;
      }
      if (!/^[^@\s]+@sha256:[a-f0-9]{64}$/iu.test(from))
        remoteCopyLines.push(instruction.line);
    }
  }

  return {
    stages,
    states,
    baseKindByFrom,
    resolvedFromByInstruction,
    remoteCopyLines,
    warnings
  };
}

export class DockerfileAnalyzer implements Analyzer {
  readonly id = 'dockerfile-security';
  readonly version = '1.0.0';

  constructor(
    private readonly readerFactory: (root: string) => DockerfileReader = (
      root
    ) => new TextFileReader(undefined, { root })
  ) {}

  /** Applies Dockerfile rules to bounded, verified input snapshots. */
  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const scanner =
      (context.options?.scannerContext as ScannerContext | undefined) ??
      (await createScannerContext(context.root));
    if (path.resolve(scanner.root) !== path.resolve(context.root))
      throw new Error(
        'scanner context root does not match the Dockerfile root'
      );
    const reader = this.readerFactory(scanner.root);
    const snapshot = context.options?.snapshot as ProjectSnapshot | undefined;
    const suppliedContentProvider = context.options?.contentProvider as
      ((file: ProjectFile) => Promise<TextFileReadResult>) | undefined;
    const contentProvider =
      suppliedContentProvider ??
      (snapshot ? snapshotContentProvider(snapshot) : undefined);
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let dockerfiles = 0;
    let eligible = 0;
    let skipped = 0;
    let failed = 0;
    let cancelled = false;
    let bytesAnalyzed = 0;
    let stageMetadataIncomplete = false;

    for (const file of scanner.files) {
      if (!/(^|\/)Dockerfile(?:\.[^/]+)?$/i.test(file.relativePath)) continue;
      eligible += 1;

      if (cancelled) {
        warnings.push(`${file.relativePath}: skipped (cancelled)`);
        skipped += 1;
        continue;
      }

      const read = contentProvider
        ? await contentProvider(file)
        : await reader.read(file.absolutePath, context.signal, file.snapshot);
      if (read.status !== 'ok') {
        warnings.push(`${file.relativePath}: skipped (${read.status})`);
        if (read.status === 'failed') failed += 1;
        else skipped += 1;
        if (read.status === 'cancelled') cancelled = true;
        continue;
      }

      dockerfiles += 1;
      bytesAnalyzed += read.bytes;
      const parsed = parseInstructions(read.content);
      const instructions = parsed.instructions;
      if (parsed.warnings.length > 0) stageMetadataIncomplete = true;
      warnings.push(
        ...parsed.warnings.map((warning) => `${file.relativePath}:${warning}`)
      );
      const rootRule = rules[0];
      const healthCheckRule = rules[5];
      const lineRules = [...rules.slice(1, 5), ...rules.slice(6)];
      const fileFindings: Finding[] = [];
      const allLines = instructions.map((item) => item.text);
      const expansionBudget: DockerExpansionBudget = {
        remainingBytes: MAX_DOCKER_EXPANSION_BYTES,
        exceeded: false
      };
      const buildArgs = globalDockerArgs(
        instructions,
        parsed.escapeChar,
        expansionBudget
      );
      const stageGraph = buildDockerStageGraph(
        instructions,
        buildArgs,
        parsed.escapeChar,
        expansionBudget
      );
      if (stageGraph.warnings.length > 0) stageMetadataIncomplete = true;
      warnings.push(
        ...stageGraph.warnings.map(
          (warning) => `${file.relativePath}:${warning}`
        )
      );
      if (expansionBudget.exceeded) {
        stageMetadataIncomplete = true;
        warnings.push(
          `${file.relativePath}: Dockerfile ARG expansion budget exceeded; image metadata is unknown`
        );
      }
      if (!stageGraph.stages.length) {
        stageMetadataIncomplete = true;
        warnings.push(
          `${file.relativePath}:1: no valid FROM stage was found; Dockerfile stage semantics are unknown`
        );
      } else {
        const finalStage = stageGraph.stages.at(-1);
        const finalState = stageGraph.states.at(-1);
        if (!finalStage || !finalState) {
          stageMetadataIncomplete = true;
          warnings.push(
            `${file.relativePath}:1: final stage metadata could not be resolved`
          );
        } else {
          if (!finalState.userKnown) {
            stageMetadataIncomplete = true;
            warnings.push(
              finalState.userUnknownReason === 'variable'
                ? `${file.relativePath}:${finalState.userLine ?? finalStage.from.line}: final stage USER uses an unresolved variable; non-root execution could not be verified`
                : finalState.userUnknownReason === 'syntax'
                  ? `${file.relativePath}:${finalState.userLine ?? finalStage.from.line}: final stage USER syntax is unsupported; non-root execution could not be verified`
                  : finalState.userUnknownReason === 'name'
                    ? `${file.relativePath}:${finalState.userLine ?? finalStage.from.line}: final stage USER is a name whose numeric identity could not be verified`
                    : `${file.relativePath}:${finalStage.from.line}: inherited/default USER metadata is unknown; non-root execution could not be verified`
            );
            if (rootRule)
              fileFindings.push(
                finding(
                  rootRule,
                  file.relativePath,
                  finalState.userLine ?? finalStage.from.line,
                  'low'
                )
              );
          } else if (rootRule?.test(finalState.user ?? '', [])) {
            fileFindings.push(
              finding(
                rootRule,
                file.relativePath,
                finalState.userLine ?? finalStage.from.line
              )
            );
          }

          if (!finalState.healthCheckKnown) {
            stageMetadataIncomplete = true;
            warnings.push(
              `${file.relativePath}:${finalStage.from.line}: inherited/default HEALTHCHECK metadata is unknown`
            );
            if (healthCheckRule)
              fileFindings.push(
                finding(
                  healthCheckRule,
                  file.relativePath,
                  finalStage.from.line,
                  'low'
                )
              );
          } else if (finalState.healthCheck !== 'active' && healthCheckRule) {
            fileFindings.push(
              finding(
                healthCheckRule,
                file.relativePath,
                finalState.healthCheckLine ?? finalStage.from.line
              )
            );
          }
        }
      }

      for (const line of stageGraph.remoteCopyLines) {
        fileFindings.push(finding(remoteCopyRule, file.relativePath, line));
      }
      for (const instruction of instructions) {
        const resolvedFrom =
          stageGraph.resolvedFromByInstruction.get(instruction);
        const baseKind = stageGraph.baseKindByFrom.get(instruction);
        for (const rule of lineRules) {
          if (
            rule.id === 'TLP-DOCKER-003' &&
            ['stage', 'scratch'].includes(baseKind ?? '')
          )
            continue;
          const modeledDefault =
            rule.id === 'TLP-DOCKER-003' &&
            resolvedFrom &&
            !resolvedFrom.line.includes('__TOOLIP_UNKNOWN_') &&
            !resolvedFrom.line.includes('__TOOLIP_BUILTIN_') &&
            !resolvedFrom.line.includes('__TOOLIP_ESCAPED_') &&
            resolvedFrom.image !== '';
          // An overridable but known ARG default is still useful evidence of
          // an unpinned image, but is only low confidence. Unknown variables
          // cannot establish either an immutably pinned or an unpinned image.
          const inspectFrom =
            rule.id !== 'TLP-DOCKER-003' ||
            (resolvedFrom !== undefined &&
              (!resolvedFrom.unresolved || modeledDefault));
          const testedLine =
            rule.id === 'TLP-DOCKER-003' && modeledDefault
              ? resolvedFrom.line
              : instruction.text;
          if (inspectFrom && rule.test(testedLine, allLines)) {
            fileFindings.push(
              finding(
                rule,
                file.relativePath,
                instruction.line,
                resolvedFrom?.unresolved && modeledDefault ? 'low' : 'high'
              )
            );
          }
        }
      }
      findings.push(...bindSourceProvenance(fileFindings, file, read));
    }

    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings,
      coverage: (() => {
        const coverage = coverageOf({
          eligible,
          scanned: dockerfiles,
          skipped,
          failed,
          cancelled
        });
        return stageMetadataIncomplete
          ? {
              ...coverage,
              state:
                coverage.state === 'failed'
                  ? ('failed' as const)
                  : ('partial' as const),
              reason:
                'one or more Dockerfile stage bases or inherited runtime metadata could not be verified'
            }
          : coverage;
      })(),
      warnings: warnings.length > 0 ? warnings : undefined,
      metadata: {
        eligibleDockerfiles: eligible,
        dockerfiles,
        bytesAnalyzed: bytesAnalyzed || reader.usage.bytesRead,
        findings: findings.length
      }
    };
  }
}
