import { analyzeAstSource } from '../analyzers/ast/source-analysis.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';
import {
  TextFileReader,
  type TextFileBudget
} from './text-file-reader.js';
import type { ToolipFinding } from './report.js';
import {
  configSecurityPatterns,
  secretPatterns,
  securityHeaderNames,
  type SecurityPattern
} from './security-patterns.js';

export type SecurityDoctorResult = {
  findings: ToolipFinding[];
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

const codeExtensions = new Set([
  'js',
  'jsx',
  'ts',
  'tsx',
  'mjs',
  'cjs'
]);

export async function runSecurityDoctor(
  rootOrContext: string | ScannerContext,
  options: SecurityDoctorOptions = {}
): Promise<SecurityDoctorResult> {
  const context = typeof rootOrContext === 'string'
    ? await createScannerContext(rootOrContext)
    : rootOrContext;
  const reader = new TextFileReader(options.budget);
  const findings: ToolipFinding[] = [];
  const warnings: string[] = [];
  let filesEligible = 0;
  let filesScanned = 0;
  let filesSkipped = 0;
  let readFailures = 0;

  for (const file of context.files) {
    if (
      !shouldScanSecrets(
        file.relativePath,
        file.extension
      )
    ) {
      continue;
    }

    filesEligible += 1;
    const read = await reader.read(
      file.absolutePath,
      options.signal
    );

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
    const content = read.content;

    findings.push(
      ...scanContent(
        file.relativePath,
        content,
        secretPatterns
      )
    );

    if (codeExtensions.has(file.extension)) {
      findings.push(
        ...analyzeAstSource(
          file.relativePath,
          content
        ).map((finding) => ({
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          message: finding.message,
          recommendation:
            finding.remediation?.summary ??
            'Review the resolved AST finding.',
          file: finding.location?.file,
          evidence:
            finding.evidence?.[0]?.summary
        }))
      );

      findings.push(
        ...scanContent(
          file.relativePath,
          content,
          configSecurityPatterns
        )
      );
    }
  }

  findings.push(
    ...detectMissingSecurityHeaders(
      context.files.map(
        (file) => file.relativePath
      )
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
      secrets: findings.filter(
        (finding) =>
          finding.category === 'secrets'
      ).length,
      dangerousCode: findings.filter(
        (finding) =>
          finding.category === 'dangerous-code'
      ).length,
      configuration: findings.filter(
        (finding) =>
          finding.category === 'configuration'
      ).length,
      headers: findings.filter(
        (finding) =>
          finding.category === 'security-headers'
      ).length
    }
  };
}

function shouldScanSecrets(
  relativePath: string,
  extension: string
): boolean {
  if (relativePath.endsWith('.d.ts')) return false;
  if (relativePath.endsWith('.map')) return false;
  if (relativePath.startsWith('dist/')) return false;
  if (relativePath.endsWith('.env')) return true;
  if (relativePath.includes('.env.')) return true;

  return secretScanExtensions.has(extension);
}

function scanContent(
  relativePath: string,
  content: string,
  patterns: SecurityPattern[]
): ToolipFinding[] {
  const findings: ToolipFinding[] = [];

  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    const match = pattern.regex.exec(content);
    pattern.regex.lastIndex = 0;

    if (!match) {
      continue;
    }

    findings.push({
      id: `${pattern.id}-${relativePath
        .toUpperCase()
        .replaceAll(/[^A-Z0-9]/g, '-')}`,
      title: formatTitle(pattern, relativePath),
      severity: resolveSeverity(
        pattern,
        relativePath
      ),
      category: pattern.category,
      message: formatMessage(
        pattern,
        relativePath
      ),
      recommendation: pattern.recommendation,
      file: relativePath,
      evidence: redactEvidence(match[0])
    });
  }

  return findings;
}

function isTestFile(relativePath: string): boolean {
  return (
    relativePath.startsWith('tests/') ||
    relativePath.includes('/tests/') ||
    relativePath.includes('/__tests__/') ||
    /\.(test|spec)\.[cm]?[jt]sx?$/.test(relativePath)
  );
}

function resolveSeverity(
  pattern: SecurityPattern,
  relativePath: string
): ToolipFinding['severity'] {
  if (
    pattern.category === 'secrets' &&
    isTestFile(relativePath)
  ) {
    return 'low';
  }

  return pattern.severity;
}

function formatTitle(
  pattern: SecurityPattern,
  relativePath: string
): string {
  if (
    pattern.category === 'secrets' &&
    isTestFile(relativePath)
  ) {
    return `Potential test fixture: ${pattern.title}`;
  }

  return pattern.title;
}

function formatMessage(
  pattern: SecurityPattern,
  relativePath: string
): string {
  if (
    pattern.category === 'secrets' &&
    isTestFile(relativePath)
  ) {
    return `${pattern.message} This match is inside a test file, so Toolip reduced its severity. Confirm that it is synthetic fixture data.`;
  }

  return pattern.message;
}

function redactEvidence(value: string): string {
  if (value.length <= 16) {
    return value;
  }

  return `${value.slice(0, 8)}...[redacted]...${value.slice(-4)}`;
}

function detectMissingSecurityHeaders(
  relativePaths: string[]
): ToolipFinding[] {
  const possibleServerFiles = relativePaths.filter(
    (file) =>
      !file.startsWith('dist/') &&
      /server|app|main|index|middleware/i.test(file) &&
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file)
  );

  if (possibleServerFiles.length === 0) {
    return [];
  }

  return securityHeaderNames.map((header) => ({
    id: `TOOLIP-HEADER-VERIFY-${header
      .toUpperCase()
      .replaceAll('-', '_')}`,
    title: `Verify security header: ${header}`,
    severity: 'info',
    category: 'security-headers',
    message: `Toolip found server-like files. Confirm that ${header} is configured in production responses.`,
    recommendation:
      'Use Helmet or equivalent framework middleware to set secure HTTP response headers.'
  }));
}
