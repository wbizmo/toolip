import { analyzeAstSource } from '../analyzers/ast/source-analysis.js';
import { type AnalysisCoverage, coverageOf } from '../contracts/analysis.js';
import type { Finding } from '../contracts/finding.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';
import {
  TextFileReader,
  type TextFileBudget,
  type TextFileReadResult
} from './text-file-reader.js';
import { bindSourceProvenance } from './source-provenance.js';
import {
  configSecurityPatterns,
  secretPatterns,
  securityHeaderNames,
  type SecurityPattern
} from './security-patterns.js';
import {
  findSecretMatches,
  isTestFile,
  secretEvidence,
  secretFingerprint,
  createFixtureSuppressionIndex,
  trustedSuppressionFor,
  type TrustedFixtureSuppression
} from './secret-utils.js';

export type SecurityDoctorResult = {
  findings: Finding[];
  /** Canonical completeness: skipped or unreadable eligible files make a run partial. */
  coverage: AnalysisCoverage;
  warnings?: string[];
  suppressedFixtures: { count: number; ids: string[] };
  summary: {
    filesDiscovered: number;
    filesEligible: number;
    filesScanned: number;
    filesSkipped: number;
    readFailures: number;
    bytesScanned: number;
    secrets: number;
    dangerousCode: number;
    configuration: number;
    headers: number;
  };
};

export type SecurityDoctorOptions = {
  budget?: TextFileBudget;
  signal?: AbortSignal;
  /**
   * Supplies file content instead of reading the worktree. Pre-commit uses this
   * to scan the exact staged blobs, never the (possibly different) working copy.
   */
  contentProvider?: (
    file: ScannerContext['files'][number]
  ) => Promise<TextFileReadResult>;
  /** Trusted caller-owned fixture policy; comments in scanned content never grant suppression. */
  trustedFixtureSuppressions?: readonly TrustedFixtureSuppression[];
};

const secretScanExtensions = new Set([
  'js',
  'jsx',
  'ts',
  'tsx',
  'mjs',
  'cjs',
  'json',
  'yml',
  'yaml',
  'env',
  'txt',
  'pem',
  'key'
]);

const codeExtensions = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);

/** Runs the local security checks and records truthful scan coverage. */
export async function runSecurityDoctor(
  rootOrContext: string | ScannerContext,
  options: SecurityDoctorOptions = {}
): Promise<SecurityDoctorResult> {
  const context =
    typeof rootOrContext === 'string'
      ? await createScannerContext(rootOrContext)
      : rootOrContext;
  const reader = new TextFileReader(options.budget, { root: context.root });
  const findings: Finding[] = [];
  const warnings: string[] = [];
  let filesEligible = 0;
  let filesScanned = 0;
  let filesSkipped = 0;
  let readFailures = 0;
  let providerBytes = 0;
  const suppressedFixtureIds: string[] = [];
  const fixturePolicy = createFixtureSuppressionIndex(
    options.trustedFixtureSuppressions
  );

  const eligibleFiles = context.files.filter((file) =>
    shouldScanSecrets(file.relativePath, file.extension)
  );
  filesEligible = eligibleFiles.length;
  let cancelled = false;

  for (const [index, file] of eligibleFiles.entries()) {
    const read = options.contentProvider
      ? await options.contentProvider(file)
      : await reader.read(file.absolutePath, options.signal, file.snapshot);
    if (options.contentProvider && read.status === 'ok') {
      providerBytes += read.bytes;
    }

    if (read.status !== 'ok') {
      filesSkipped += 1;
      if (read.status === 'failed') {
        readFailures += 1;
        warnings.push(`${file.relativePath}: ${read.error}`);
      } else {
        warnings.push(`${file.relativePath}: skipped (${read.status})`);
      }

      if (read.status === 'cancelled') {
        // Files after the cancellation point were never examined: count them
        // so the run cannot look complete.
        cancelled = true;
        filesSkipped += eligibleFiles.length - index - 1;
        break;
      }
      continue;
    }

    filesScanned += 1;
    const fileFindings = scanSecretContent(file.relativePath, read.content);
    const allowedFindings = fileFindings.filter((finding) => {
      const policy = trustedSuppressionFor(
        fixturePolicy,
        finding.ruleId,
        file.relativePath
      );
      if (!policy) return true;
      suppressedFixtureIds.push(policy.id);
      return false;
    });

    if (codeExtensions.has(file.extension)) {
      allowedFindings.push(
        ...analyzeAstSource(file.relativePath, read.content),
        ...scanConfigurationContent(file.relativePath, read.content)
      );
    }
    findings.push(...bindSourceProvenance(allowedFindings, file, read));
  }

  findings.push(
    ...detectMissingSecurityHeaders(
      context.files.map((file) => file.relativePath)
    )
  );

  return {
    findings,
    coverage: coverageOf({
      eligible: filesEligible,
      scanned: filesScanned,
      skipped: filesSkipped - readFailures,
      failed: readFailures,
      excluded: context.files.length - filesEligible,
      cancelled
    }),
    warnings: warnings.length > 0 ? warnings : undefined,
    suppressedFixtures: {
      count: suppressedFixtureIds.length,
      ids: [...new Set(suppressedFixtureIds)]
    },
    summary: {
      filesDiscovered: context.files.length,
      filesEligible,
      filesScanned,
      filesSkipped,
      readFailures,
      bytesScanned: reader.usage.bytesRead + providerBytes,
      secrets: countCategory(findings, 'secrets'),
      dangerousCode: countCategory(findings, 'dangerous-code'),
      configuration: countCategory(findings, 'configuration'),
      headers: countCategory(findings, 'security-headers')
    }
  };
}

/** Counts findings belonging to one canonical finding category. */
function countCategory(findings: Finding[], category: string): number {
  return findings.filter((finding) => finding.category === category).length;
}

/** Identifies source and configuration files eligible for secret inspection. */
export function shouldScanSecrets(
  relativePath: string,
  extension: string
): boolean {
  if (relativePath.endsWith('.d.ts')) return false;
  if (relativePath.endsWith('.map')) return false;
  if (relativePath.startsWith('dist/')) return false;
  if (relativePath.endsWith('.env')) return true;
  if (relativePath.includes('.env.')) return true;
  const basename = relativePath.split('/').at(-1)?.toLowerCase() ?? '';
  if (
    /^(\.npmrc|\.pypirc|\.netrc|\.env(?:\..*)?|credentials(?:\..*)?|secrets?(?:\..*)?)$/.test(
      basename
    )
  )
    return true;
  const binaryExtensions = new Set([
    '7z',
    'a',
    'avi',
    'bin',
    'bmp',
    'class',
    'dll',
    'dylib',
    'exe',
    'gif',
    'gz',
    'ico',
    'jar',
    'jpeg',
    'jpg',
    'mp3',
    'mp4',
    'o',
    'pdf',
    'png',
    'so',
    'sqlite',
    'tar',
    'wasm',
    'webp',
    'zip'
  ]);
  return (
    secretScanExtensions.has(extension) || !binaryExtensions.has(extension)
  );
}

/** Produces secret findings from a single already-read source file. */
function scanSecretContent(relativePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const testFile = isTestFile(relativePath);

  for (const pattern of secretPatterns) {
    for (const match of findSecretMatches(content, pattern.regex)) {
      const evidence = secretEvidence(match.value);
      findings.push({
        id: `${pattern.id}:${relativePath}:${match.line}:${match.column}`,
        ruleId: pattern.id,
        title: testFile
          ? `Potential test fixture: ${pattern.title}`
          : pattern.title,
        severity: pattern.severity,
        confidence: testFile ? 'medium' : 'high',
        category: pattern.category,
        message: testFile
          ? `${pattern.message} The value is in a test file, but severity is preserved until it is explicitly identified as synthetic fixture data.`
          : pattern.message,
        source: 'security-doctor',
        remediation: { summary: pattern.recommendation },
        location: {
          file: relativePath,
          line: match.line,
          column: match.column
        },
        evidence: [evidence],
        metadata: {
          testFixtureCandidate: testFile,
          occurrenceFingerprint: match.fingerprint
        }
      });
    }
  }

  return findings;
}

/** Inspects configuration text for unsafe security settings. */
function scanConfigurationContent(
  relativePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of configSecurityPatterns) {
    const regex = globalRegex(pattern.regex);
    for (const match of content.matchAll(regex)) {
      const index = match.index ?? 0;
      const before = content.slice(0, index);
      const line = before.split('\n').length;
      const column = index - before.lastIndexOf('\n');
      const fingerprint = secretFingerprint(
        `${pattern.id}:${relativePath}:${line}:${column}`
      );

      findings.push(
        patternFinding(pattern, relativePath, line, column, fingerprint)
      );
    }
  }

  return findings;
}

/** Builds a finding from a matched security configuration pattern. */
function patternFinding(
  pattern: SecurityPattern,
  relativePath: string,
  line: number,
  column: number,
  fingerprint: string
): Finding {
  return {
    id: `${pattern.id}:${relativePath}:${line}:${column}`,
    ruleId: pattern.id,
    title: pattern.title,
    severity: pattern.severity,
    confidence: 'medium',
    category: pattern.category,
    message: pattern.message,
    source: 'security-doctor',
    remediation: { summary: pattern.recommendation },
    location: { file: relativePath, line, column },
    evidence: [
      {
        summary: '[configuration pattern matched]',
        fingerprint
      }
    ]
  };
}

/** Returns a fresh global regex so repeated scans do not share lastIndex. */
function globalRegex(pattern: RegExp): RegExp {
  return new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
  );
}

/** Reports missing baseline HTTP security headers from project configuration. */
function detectMissingSecurityHeaders(relativePaths: string[]): Finding[] {
  const possibleServerFiles = relativePaths.filter(
    (file) =>
      !file.startsWith('dist/') &&
      /server|app|main|index|middleware/i.test(file) &&
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file)
  );

  if (possibleServerFiles.length === 0) return [];

  return securityHeaderNames.map((header) => ({
    id: `TOOLIP-HEADER-VERIFY-${header.toUpperCase().replaceAll('-', '_')}`,
    ruleId: 'TOOLIP-HEADER-VERIFY',
    title: `Verify security header: ${header}`,
    severity: 'info',
    confidence: 'low',
    category: 'security-headers',
    message: `Toolip found server-like files. Confirm that ${header} is configured in production responses.`,
    source: 'security-doctor',
    remediation: {
      summary:
        'Use Helmet or equivalent framework middleware to set secure HTTP response headers.'
    },
    metadata: {
      header,
      heuristic: true
    }
  }));
}
