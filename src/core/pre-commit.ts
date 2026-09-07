import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Finding } from '../contracts/finding.js';
import { ToolipError } from '../errors/toolip-error.js';
import { runGitAudit } from './git-audit.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';
import { runSecurityDoctor } from './security-doctor.js';

const execFileAsync = promisify(execFile);

export type PreCommitOptions = {
  full?: boolean;
};

export type PreCommitResult = {
  passed: boolean;
  findings: Finding[];
  scope: 'staged' | 'full';
  filesConsidered: number;
  summary: {
    critical: number;
    high: number;
    blocking: number;
  };
};

export async function runPreCommit(
  root: string,
  options: PreCommitOptions = {}
): Promise<PreCommitResult> {
  const context = await createScannerContext(root);
  const staged = options.full
    ? undefined
    : await readStagedPaths(context.root);
  const analysisContext = staged
    ? scopedContext(context, staged)
    : context;

  const [doctor, gitAudit] = await Promise.all([
    runSecurityDoctor(analysisContext),
    runGitAudit(analysisContext)
  ]);

  const combined = [...doctor.findings, ...gitAudit.findings];
  const findings = staged
    ? combined.filter((finding) => findingAppliesToStagedScope(finding, staged))
    : combined;
  const critical = findings.filter((finding) => finding.severity === 'critical').length;
  const high = findings.filter((finding) => finding.severity === 'high').length;
  const blocking = critical + high;

  return {
    passed: blocking === 0,
    findings,
    scope: staged ? 'staged' : 'full',
    filesConsidered: analysisContext.files.length,
    summary: {
      critical,
      high,
      blocking
    }
  };
}

async function readStagedPaths(root: string): Promise<Set<string>> {
  try {
    const { stdout } = await execFileAsync(
      'git',
      [
        'diff',
        '--cached',
        '--name-only',
        '--diff-filter=ACMR',
        '--relative',
        '-z'
      ],
      {
        cwd: root,
        encoding: 'utf8',
        maxBuffer: 4 * 1024 * 1024
      }
    );

    return new Set(
      String(stdout)
        .split('\0')
        .filter(Boolean)
        .map(normalizePath)
    );
  } catch {
    throw new ToolipError(
      'Pre-commit staged scanning requires a Git working tree. Use --full only for an explicit repository-wide manual check.',
      {
        code: 'PRE_COMMIT_GIT_REQUIRED',
        exitCode: 1
      }
    );
  }
}

function scopedContext(
  context: ScannerContext,
  staged: ReadonlySet<string>
): ScannerContext {
  const files = context.files.filter((file) => staged.has(file.relativePath));

  return {
    ...context,
    files,
    summary: {
      totalFiles: files.length,
      extensions: files.reduce<Record<string, number>>((summary, file) => {
        const key = file.extension || 'none';
        summary[key] = (summary[key] ?? 0) + 1;
        return summary;
      }, {})
    }
  };
}

function findingAppliesToStagedScope(
  finding: Finding,
  staged: ReadonlySet<string>
): boolean {
  if (finding.location?.file) {
    return staged.has(normalizePath(finding.location.file));
  }

  return finding.category === 'git-security' && staged.has('.gitignore');
}

function normalizePath(value: string): string {
  return value.replaceAll('\\', '/').replace(/^\.\//, '');
}
