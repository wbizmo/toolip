import { readFile } from 'node:fs/promises';
import { createScannerContext } from './scanner-context.js';
import type { ToolipFinding } from './report.js';
import {
  configSecurityPatterns,
  dangerousCodePatterns,
  secretPatterns,
  securityHeaderNames,
  type SecurityPattern
} from './security-patterns.js';

export type SecurityDoctorResult = {
  findings: ToolipFinding[];
  summary: {
    filesScanned: number;
    secrets: number;
    dangerousCode: number;
    configuration: number;
    headers: number;
  };
};

const scanExtensions = new Set([
  'js',
  'jsx',
  'ts',
  'tsx',
  'json',
  'yml',
  'yaml',
  'env',
  'txt',
  'pem',
  'key'
]);

export async function runSecurityDoctor(root: string): Promise<SecurityDoctorResult> {
  const context = await createScannerContext(root);
  const findings: ToolipFinding[] = [];

  for (const file of context.files) {
    if (!shouldScan(file.relativePath, file.extension)) continue;

    let content = '';

    try {
      content = await readFile(file.absolutePath, 'utf8');
    } catch {
      continue;
    }

    findings.push(...scanContent(file.relativePath, content, secretPatterns));
    findings.push(...scanContent(file.relativePath, content, dangerousCodePatterns));
    findings.push(...scanContent(file.relativePath, content, configSecurityPatterns));
  }

  findings.push(...detectMissingSecurityHeaders(context.files.map((file) => file.relativePath)));

  return {
    findings,
    summary: {
      filesScanned: context.files.length,
      secrets: findings.filter((finding) => finding.category === 'secrets').length,
      dangerousCode: findings.filter((finding) => finding.category === 'dangerous-code').length,
      configuration: findings.filter((finding) => finding.category === 'configuration').length,
      headers: findings.filter((finding) => finding.category === 'security-headers').length
    }
  };
}

function shouldScan(relativePath: string, extension: string): boolean {
  if (relativePath.endsWith('.env')) return true;
  if (relativePath.includes('.env.')) return true;
  if (scanExtensions.has(extension)) return true;
  return false;
}

function scanContent(
  relativePath: string,
  content: string,
  patterns: SecurityPattern[]
): ToolipFinding[] {
  const findings: ToolipFinding[] = [];

  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    const matches = content.match(pattern.regex);

    if (!matches) continue;

    findings.push({
      id: `${pattern.id}-${relativePath.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
      title: pattern.title,
      severity: pattern.severity,
      category: pattern.category,
      message: pattern.message,
      recommendation: pattern.recommendation,
      file: relativePath,
      evidence: redactEvidence(matches[0])
    });
  }

  return findings;
}

function redactEvidence(value: string): string {
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}...[redacted]...${value.slice(-4)}`;
}

function detectMissingSecurityHeaders(relativePaths: string[]): ToolipFinding[] {
  const possibleServerFiles = relativePaths.filter((file) =>
    /server|app|main|index|middleware/i.test(file) &&
    /\.(js|ts|jsx|tsx)$/.test(file)
  );

  if (possibleServerFiles.length === 0) {
    return [];
  }

  const findings: ToolipFinding[] = [];

  for (const header of securityHeaderNames) {
    findings.push({
      id: `TOOLIP-HEADER-VERIFY-${header.toUpperCase().replaceAll('-', '_')}`,
      title: `Verify security header: ${header}`,
      severity: 'info',
      category: 'security-headers',
      message: `Toolip found server-like files. Confirm that ${header} is configured in production responses.`,
      recommendation: 'Use Helmet or equivalent framework middleware to set secure HTTP response headers.'
    });
  }

  return findings;
}
