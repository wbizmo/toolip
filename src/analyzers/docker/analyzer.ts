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

function declaresLiteralSecret(line: string): boolean {
  const match = line
    .trim()
    .match(/^(?:ARG|ENV)\s+([A-Za-z_][\w-]*)(?:=(.*)|\s+(.+))?$/i);
  if (
    !match ||
    !/(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|PRIVATE[_-]?KEY)/i.test(
      match[1] ?? ''
    )
  ) {
    return false;
  }
  return Boolean((match[2] ?? match[3] ?? '').trim());
}

const rules: DockerRule[] = [
  {
    id: 'TLP-DOCKER-001',
    title: 'Container may run as root',
    severity: 'high',
    test: (_line, lines) => {
      const lastUser = lines
        .filter((line) => /^USER\s+/iu.test(line.trim()))
        .at(-1);
      if (!lastUser) return true;
      const identity = lastUser.trim().replace(/^USER\s+/iu, '').split(/\s/u)[0];
      if (!identity || identity.includes('$')) return false;
      const username = identity.split(':', 1)[0] ?? '';
      if (username.toLowerCase() === 'root') return true;
      if (/^\d+$/u.test(username)) {
        try {
          return BigInt(username) === 0n;
        } catch {
          return false;
        }
      }
      return false;
    },
    message: 'No non-root USER instruction was found.',
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
    test: (line) =>
      /^FROM\s+\S+(?::latest)?(?:\s|$)/i.test(line.trim()) &&
      !/@sha256:/i.test(line),
    message: 'The base image is not pinned by digest.',
    remediation:
      'Pin trusted base images by immutable digest and review updates deliberately.'
  },
  {
    id: 'TLP-DOCKER-004',
    title: 'Remote ADD instruction',
    severity: 'high',
    test: (line) => /^ADD\s+https?:\/\//i.test(line.trim()),
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
    message:
      'The final Dockerfile stage has no active HEALTHCHECK instruction; inherited image metadata is not inspected.',
    remediation:
      'Add a HEALTHCHECK when the runtime can report meaningful service health.'
  },
  {
    id: 'TLP-DOCKER-007',
    title: 'Remote content is executed during the image build',
    severity: 'high',
    test: (line) =>
      /^RUN\s+/i.test(line.trim()) &&
      /(?:curl|wget)\b[^\n;&|]{0,300}(?:\||&&|;)[ \t]*(?:sh|bash|ash)\b/i.test(
        line
      ),
    message:
      'The build downloads and executes remote content without a pinned, independently verified artifact.',
    remediation:
      'Fetch a pinned artifact, verify its digest or signature, and execute it only after verification.'
  }
];

/** Creates the canonical finding for one Dockerfile rule match. */
function finding(
  rule: DockerRule,
  relativePath: string,
  lineNumber: number
): Finding {
  return {
    id: `${rule.id}:${relativePath}:${lineNumber}`,
    ruleId: rule.id,
    title: rule.title,
    category: 'container',
    severity: rule.severity,
    confidence: 'high',
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

function globalDockerArgs(
  instructions: readonly DockerInstruction[]
): Map<string, string | undefined> {
  const values = new Map<string, string | undefined>();
  for (const instruction of instructions) {
    if (/^FROM\s+/iu.test(instruction.text)) break;
    const declaration = instruction.text.match(/^ARG\s+([A-Za-z_][\w]*)(?:=(.*))?$/iu);
    if (!declaration?.[1]) continue;
    const value = declaration[2];
    const expanded =
      value === undefined ? undefined : expandBuildArgs(value, values);
    values.set(
      declaration[1],
      expanded === undefined || expanded.unresolved ? undefined : expanded.value
    );
  }
  return values;
}

function expandBuildArgs(
  source: string,
  values: ReadonlyMap<string, string | undefined>
): { value: string; unresolved: boolean } {
  let unresolved = false;
  const value = source.replace(
    /\$\{([A-Za-z_][\w]*)(?:(:-|-)([^}]*))?\}|\$([A-Za-z_][\w]*)/gu,
    (_whole, bracedName: string | undefined, operator: string | undefined, fallback: string | undefined, plainName: string | undefined) => {
      const name = bracedName ?? plainName ?? '';
      if (builtinBuildArgs.has(name)) return `__TOOLIP_BUILTIN_${name}__`;
      const resolved = values.get(name);
      if (resolved !== undefined && !(operator === ':-' && resolved === ''))
        return resolved;
      if (operator) return fallback ?? '';
      unresolved = true;
      return `__TOOLIP_UNKNOWN_${name}__`;
    }
  );
  return { value, unresolved };
}

function resolveFromImage(
  instruction: DockerInstruction,
  buildArgs: ReadonlyMap<string, string | undefined>
): { line: string; unresolved: boolean } | undefined {
  const match = instruction.text.match(/^FROM\s+(.+)$/iu);
  if (!match?.[1]) return undefined;
  const tokens = match[1].trim().split(/\s+/u);
  let imageIndex = 0;
  while (tokens[imageIndex]?.startsWith('--')) imageIndex++;
  if (imageIndex >= tokens.length) return undefined;
  const expanded = expandBuildArgs(tokens[imageIndex] ?? '', buildArgs);
  tokens[imageIndex] = expanded.value;
  return { line: `FROM ${tokens.join(' ')}`, unresolved: expanded.unresolved };
}

function parseInstructions(source: string): DockerInstruction[] {
  const physical = source.split(/\r?\n/u);
  const escapeDirective = physical.find((line) =>
    /^\s*#\s*escape=/i.test(line)
  );
  const escapeChar =
    escapeDirective?.match(/^\s*#\s*escape=(.)\s*$/i)?.[1] ?? '\\';
  const instructions: DockerInstruction[] = [];
  let buffer = '';
  let startLine = 1;

  for (const [index, original] of physical.entries()) {
    const lineNumber = index + 1;
    const line = original.trimEnd();
    if (!buffer && (!line.trim() || /^\s*#/u.test(line))) continue;
    if (!buffer) startLine = lineNumber;

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
    buffer = buffer ? `${buffer} ${fragment}` : fragment;
    if (continued) continue;

    if (/^\s*[A-Za-z]+(?:\s+|$)/u.test(buffer)) {
      instructions.push({ line: startLine, text: buffer });
    }
    buffer = '';
  }
  if (buffer && /^\s*[A-Za-z]+(?:\s+|$)/u.test(buffer)) {
    instructions.push({ line: startLine, text: buffer });
  }
  return instructions;
}

function finalStage(instructions: DockerInstruction[]): {
  instructions: DockerInstruction[];
  lines: string[];
  fromLine: number;
} {
  let start = instructions.findIndex((item) => /^\s*FROM\s+/i.test(item.text));
  for (let index = start + 1; index < instructions.length; index++) {
    if (/^\s*FROM\s+/i.test(instructions[index]?.text ?? '')) start = index;
  }
  const finalInstructions = instructions.slice(Math.max(0, start));
  return {
    instructions: finalInstructions,
    lines: finalInstructions.map((item) => item.text),
    fromLine: instructions[Math.max(0, start)]?.line ?? 1
  };
}

function finalUserInstruction(
  instructions: readonly DockerInstruction[]
): DockerInstruction | undefined {
  return instructions
    .filter((instruction) => /^USER\s+/iu.test(instruction.text.trim()))
    .at(-1);
}

function finalHealthCheckInstruction(
  instructions: readonly DockerInstruction[]
): DockerInstruction | undefined {
  return instructions
    .filter((instruction) =>
      /^HEALTHCHECK\s+/iu.test(instruction.text.trim())
    )
    .at(-1);
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
      const instructions = parseInstructions(read.content);
      const rootRule = rules[0];
      const healthCheckRule = rules[5];
      const lineRules = [...rules.slice(1, 5), ...rules.slice(6)];
      const fileFindings: Finding[] = [];
      const final = finalStage(instructions);
      const allLines = instructions.map((item) => item.text);
      const buildArgs = globalDockerArgs(instructions);
      const lastUser = finalUserInstruction(final.instructions);
      const userValue = lastUser?.text
        .trim()
        .replace(/^USER\s+/iu, '')
        .split(/\s/u)[0];
      const unresolvedFinalUser = Boolean(userValue?.includes('$'));
      if (unresolvedFinalUser) {
        warnings.push(
          `${file.relativePath}:${lastUser?.line ?? final.fromLine}: final stage USER uses an unresolved variable; non-root execution could not be verified`
        );
      }

      if (!unresolvedFinalUser && rootRule?.test('', final.lines)) {
        fileFindings.push(
          finding(
            rootRule,
            file.relativePath,
            lastUser?.line ?? final.fromLine
          )
        );
      }

      if (healthCheckRule?.test('', final.lines)) {
        const lastHealthCheck = finalHealthCheckInstruction(final.instructions);
        fileFindings.push(
          finding(
            healthCheckRule,
            file.relativePath,
            lastHealthCheck?.line ?? final.fromLine
          )
        );
      }

      for (const instruction of instructions) {
        const resolvedFrom = resolveFromImage(instruction, buildArgs);
        if (resolvedFrom?.unresolved) {
          warnings.push(
            `${file.relativePath}:${instruction.line}: base image uses an unresolved build argument; digest pinning could not be verified`
          );
        }
        for (const rule of lineRules) {
          const testedLine =
            rule.id === 'TLP-DOCKER-003' && resolvedFrom && !resolvedFrom.unresolved
              ? resolvedFrom.line
              : instruction.text;
          if (
            !(rule.id === 'TLP-DOCKER-003' && resolvedFrom?.unresolved) &&
            rule.test(testedLine, allLines)
          ) {
            fileFindings.push(
              finding(
                rule,
                file.relativePath,
                instruction.line
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
        const unresolvedFromArgs = warnings.some((warning) =>
          warning.includes('base image uses an unresolved build argument') ||
          warning.includes('final stage USER uses an unresolved variable')
        );
        return unresolvedFromArgs
          ? {
              ...coverage,
              state:
                coverage.state === 'failed'
                  ? ('failed' as const)
                  : ('partial' as const),
              reason:
                'one or more base image or final USER references could not be resolved'
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
