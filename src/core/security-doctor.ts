import { analyzeAstSource } from '../analyzers/ast/source-analysis.js';
import type { Finding } from '../contracts/finding.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';
import {
  TextFileReader,
  type TextFileBudget
} from './text-file-reader.js';
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
  secretFingerprint
} from './secret-utils.js';

export type SecurityDoctorResult = {
  findings: Finding[];
  warnings?: string[];
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
};

const secretScanExtensions = new Set([
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs',
  'json', 'yml', 'yaml', 'env', 'txt', 'pem', 'key'
]);

const codeExtensions = new Set([
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'
]);

export async function runSecurityDoctor(
  rootOrContext: string | ScannerContext,
  options: SecurityDoctorOptions = {}
): Promise<SecurityDoctorResult> {
  const context = typeof rootOrContext === 'string'
    ? await createScannerContext(rootOrContext)
    : rootOrContext;
  const reader = new TextFileReader(options.budget);
  const findings: Finding[] = [];
  const warnings: string[] = [];
  let filesEligible = 0;
  let filesScanned = 0;
  let filesSkipped = 0;
  let readFailures = 0;

  for (const file of context.files) {
    if (!shouldScanSecrets(file.relativePath, file.extension)) continue;

    filesEligible += 1;
    const read = await reader.read(file.absolutePath, options.signal);

    if (read.status !== 'ok') {
      filesSkipped += 1;
      if (read.status === 'failed') {
        readFailures += 1;
        warnings.push(`${file.relativePath}: ${read.error}`);
      } else {
        warnings.push(`${file.relativePath}: skipped (${read.status})`);
      }

      if (read.status === 'cancelled') break;
      continue;
    }

    filesScanned += 1;
    findings.push(
      ...scanSecretContent(file.relativePath, read.content)
    );

    if (codeExtensions.has(file.extension)) {
      findings.push(
        ...analyzeAstSource(file.relativePath, read.content),
        ...scanConfigurationContent(file.relativePath, read.content)
      );
    }
  }

  findings.push(
    ...detectMissingSecurityHeaders(
      context.files.map((file) => file.relativePath)
    )
  );

  return {
    findings,
    warnings: warnings.length > 0 ? warnings : undefined,
    summary: {
      filesDiscovered: context.files.length,
      filesEligible,
      filesScanned,
      filesSkipped,
      readFailures,
      bytesScanned: reader.usage.bytesRead,
      secrets: countCategory(findings, 'secrets'),
      dangerousCode: countCategory(findings, 'dangerous-code'),
      configuration: countCategory(findings, 'configuration'),
      headers: countCategory(findings, 'security-headers')
    }
  };
}

function countCategory(findings: Finding[], category: string): number {
  return findings.filter((finding) => finding.category === category).length;
}

function shouldScanSecrets(relativePath: string, extension: string): boolean {
  if (relativePath.endsWith('.d.ts')) return false;
  if (relativePath.endsWith('.map')) return false;
  if (relativePath.startsWith('dist/')) return false;
  if (relativePath.endsWith('.env')) return true;
  if (relativePath.includes('.env.')) return true;
  return secretScanExtensions.has(extension);
}

function scanSecretContent(
  relativePath: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];
  const testFile = isTestFile(relativePath);

  for (const pattern of secretPatterns) {
    for (const match of findSecretMatches(content, pattern.regex)) {
      if (match.fixtureAllowed) continue;

      const evidence = secretEvidence(match.value);
      const instance = match.fingerprint.slice(0, 16);

      findings.push({
        id: `${pattern.id}:${relativePath}:${match.line}:${match.column}:${instance}`,
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

      findings.push(patternFinding(
        pattern,
        relativePath,
        line,
        column,
        fingerprint
      ));
    }
  }

  return findings;
}

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
    evidence: [{
      summary: '[configuration pattern matched]',
      fingerprint
    }]
  };
}

function globalRegex(pattern: RegExp): RegExp {
  return new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
  );
}

function detectMissingSecurityHeaders(relativePaths: string[]): Finding[] {
  const possibleServerFiles = relativePaths.filter(
    (file) =>
      !file.startsWith('dist/') &&
      /server|app|main|index|middleware/i.test(file) &&
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file)
  );

  if (possibleServerFiles.length === 0) return [];

  return securityHeaderNames.map((header) => ({
    id: `TOOLIP-HEADER-VERIFY-${header
      .toUpperCase()
      .replaceAll('-', '_')}`,
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
