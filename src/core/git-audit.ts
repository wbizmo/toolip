import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { walkProjectFiles } from './file-walker.js';
import type { ToolipFinding } from './report.js';

export type GitAuditResult = {
  findings: ToolipFinding[];
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

export async function runGitAudit(root: string): Promise<GitAuditResult> {
  const files = await walkProjectFiles(root);
  const relativePaths = files.map((file) => file.relativePath);
  const gitignorePath = path.join(root, '.gitignore');
  const gitignorePresent = await exists(gitignorePath);
  const gitignoreContent = gitignorePresent ? await readFile(gitignorePath, 'utf8') : '';

  const findings: ToolipFinding[] = [];

  for (const file of relativePaths) {
    for (const pattern of dangerousFilePatterns) {
      if (!pattern.regex.test(file)) continue;

      findings.push({
        id: `TOOLIP-GIT-${pattern.id}-${file.toUpperCase().replaceAll(/[^A-Z0-9]/g, '-')}`,
        title: pattern.title,
        severity: pattern.severity,
        category: 'git-security',
        message: pattern.message,
        recommendation: pattern.recommendation,
        file
      });
    }
  }

  const envIgnored = ignoresPattern(gitignoreContent, '.env') || ignoresPattern(gitignoreContent, '.env.*');
  const pemIgnored = ignoresPattern(gitignoreContent, '*.pem') || ignoresPattern(gitignoreContent, '.pem');

  if (!gitignorePresent) {
    findings.push({
      id: 'TOOLIP-GIT-MISSING-GITIGNORE',
      title: 'Missing .gitignore',
      severity: 'medium',
      category: 'git-security',
      message: 'No .gitignore file was found.',
      recommendation: 'Add a .gitignore file that excludes secrets, build output, dependencies, and local machine files.'
    });
  }

  if (gitignorePresent && !envIgnored) {
    findings.push({
      id: 'TOOLIP-GIT-ENV-NOT-IGNORED',
      title: '.env files may not be ignored',
      severity: 'high',
      category: 'git-security',
      message: '.gitignore does not appear to ignore .env files.',
      recommendation: 'Add .env and .env.* to .gitignore while allowing a safe .env.example.'
    });
  }

  if (gitignorePresent && !pemIgnored) {
    findings.push({
      id: 'TOOLIP-GIT-PEM-NOT-IGNORED',
      title: 'PEM files may not be ignored',
      severity: 'medium',
      category: 'git-security',
      message: '.gitignore does not appear to ignore PEM files.',
      recommendation: 'Add *.pem and other key material patterns to .gitignore.'
    });
  }

  return {
    findings,
    summary: {
      filesChecked: files.length,
      dangerousFiles: findings.filter((finding) => finding.file).length,
      gitignorePresent,
      envIgnored,
      pemIgnored
    }
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
