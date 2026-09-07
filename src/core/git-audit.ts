import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding } from '../contracts/finding.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';

export type GitAuditResult = {
  findings: Finding[];
  summary: {
    filesChecked: number;
    dangerousFiles: number;
    gitignorePresent: boolean;
    envIgnored: boolean;
    pemIgnored: boolean;
  };
};

const dangerousFilePatterns = [
  {
    id: 'ENV-FILE',
    regex: /(^|\/)\.env(\.|$|\/)?/i,
    title: '.env file present',
    severity: 'high' as const,
    message: 'A .env-style file exists in the project tree.',
    recommendation: 'Keep .env files local, ensure they are ignored, and never commit real secrets.'
  },
  {
    id: 'PEM-FILE',
    regex: /\.pem$/i,
    title: 'PEM file present',
    severity: 'critical' as const,
    message: 'A PEM key file exists in the project tree.',
    recommendation: 'Remove private key files from the repository and rotate affected credentials.'
  },
  {
    id: 'KEY-FILE',
    regex: /\.(key|p12|pfx)$/i,
    title: 'Key/certificate file present',
    severity: 'critical' as const,
    message: 'A key or certificate-like file exists in the project tree.',
    recommendation: 'Do not store key material in source repositories.'
  }
];

export async function runGitAudit(
  rootOrContext: string | ScannerContext
): Promise<GitAuditResult> {
  const context = typeof rootOrContext === 'string'
    ? await createScannerContext(rootOrContext)
    : rootOrContext;
  const relativePaths = context.files.map((file) => file.relativePath);
  const gitignorePath = path.join(context.root, '.gitignore');
  const gitignorePresent = await exists(gitignorePath);
  const gitignoreContent = gitignorePresent ? await readFile(gitignorePath, 'utf8') : '';
  const findings: Finding[] = [];

  for (const file of relativePaths) {
    for (const pattern of dangerousFilePatterns) {
      if (!pattern.regex.test(file)) continue;

      findings.push({
        id: `TOOLIP-GIT-${pattern.id}-${file.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
        ruleId: `TOOLIP-GIT-${pattern.id}`,
        title: pattern.title,
        severity: pattern.severity,
        confidence: 'high',
        category: 'git-security',
        message: pattern.message,
        source: 'git-audit',
        location: { file },
        remediation: { summary: pattern.recommendation }
      });
    }
  }

  const envIgnored = ignoresPattern(gitignoreContent, '.env') || ignoresPattern(gitignoreContent, '.env.*');
  const pemIgnored = ignoresPattern(gitignoreContent, '*.pem') || ignoresPattern(gitignoreContent, '.pem');

  if (!gitignorePresent) {
    findings.push(gitFinding(
      'TOOLIP-GIT-MISSING-GITIGNORE',
      'Missing .gitignore',
      'medium',
      'No .gitignore file was found.',
      'Add a .gitignore file that excludes secrets, build output, dependencies, and local machine files.'
    ));
  }

  if (gitignorePresent && !envIgnored) {
    findings.push(gitFinding(
      'TOOLIP-GIT-ENV-NOT-IGNORED',
      '.env files may not be ignored',
      'high',
      '.gitignore does not appear to ignore .env files.',
      'Add .env and .env.* to .gitignore while allowing a safe .env.example.'
    ));
  }

  if (gitignorePresent && !pemIgnored) {
    findings.push(gitFinding(
      'TOOLIP-GIT-PEM-NOT-IGNORED',
      'PEM files may not be ignored',
      'medium',
      '.gitignore does not appear to ignore PEM files.',
      'Add *.pem and other key material patterns to .gitignore.'
    ));
  }

  return {
    findings,
    summary: {
      filesChecked: context.files.length,
      dangerousFiles: findings.filter((finding) => finding.location?.file).length,
      gitignorePresent,
      envIgnored,
      pemIgnored
    }
  };
}

function gitFinding(
  id: string,
  title: string,
  severity: Finding['severity'],
  message: string,
  recommendation: string
): Finding {
  return {
    id,
    ruleId: id,
    title,
    severity,
    confidence: 'high',
    category: 'git-security',
    message,
    source: 'git-audit',
    remediation: { summary: recommendation }
  };
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function ignoresPattern(gitignore: string, pattern: string): boolean {
  return gitignore
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .some((line) => line === pattern || line.includes(pattern));
}
