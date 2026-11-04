import path from 'node:path';
import type { Finding } from '../contracts/finding.js';
import { ToolipError } from '../errors/toolip-error.js';
import { runGitAudit } from './git-audit.js';
import { listStagedEntries, readBlobs } from './git/staged-index.js';
import { loadToolipIgnore } from './load-toolip-ignore.js';
import type { ProjectFile } from './file-walker.js';
import { profileProject } from './profile-project.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';
import { runSecurityDoctor } from './security-doctor.js';
import {
  defaultTextFileBudget,
  type TextFileReadResult
} from './text-file-reader.js';

export type PreCommitOptions = {
  full?: boolean;
  signal?: AbortSignal;
};

export type PreCommitResult = {
  passed: boolean;
  findings: Finding[];
  scope: 'staged' | 'full';
  filesConsidered: number;
  /** Staged paths that were not content-scanned (binary, oversized, symlink, submodule). */
  warnings: string[];
  summary: {
    critical: number;
    high: number;
    blocking: number;
  };
};

/**
 * Pre-commit analysis. In staged mode (the default) the bytes that are scanned
 * are the staged blobs read from the Git object database, never the working
 * tree, so partial staging, deleted/renamed worktree files and a clean
 * working copy next to a dirty index cannot change the verdict. Any failure to
 * read the index rejects (the hook fails closed). `full` is an explicit,
 * worktree-wide manual check.
 *
 * Complexity: O(S + B) for S staged paths and B staged blob bytes (bounded by
 * the text-file budget); the worktree is not walked in staged mode.
 */
export async function runPreCommit(
  root: string,
  options: PreCommitOptions = {}
): Promise<PreCommitResult> {
  if (options.full) {
    const context = await createScannerContext(root);
    return summarize(
      await analyze(context, undefined, options.signal),
      context.files.length,
      'full',
      []
    );
  }

  const absoluteRoot = path.resolve(root);
  const snapshot = await listStagedEntries(absoluteRoot, options.signal);
  const toolipIgnore = await loadToolipIgnore(absoluteRoot);
  const entries = snapshot.entries.filter(
    (entry) => !toolipIgnore.ignores(path.join(absoluteRoot, entry.path))
  );
  const blobs = await readBlobs(
    absoluteRoot,
    entries.map((entry) => entry.oid),
    defaultTextFileBudget,
    options.signal
  );
  const oidByPath = new Map(entries.map((entry) => [entry.path, entry.oid]));

  const files: ProjectFile[] = entries
    .map((entry) => ({
      absolutePath: path.join(absoluteRoot, entry.path),
      relativePath: entry.path,
      extension: path.extname(entry.path).replace('.', '').toLowerCase()
    }))
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath));

  const context: ScannerContext = {
    root: absoluteRoot,
    profile: await profileProject(absoluteRoot, files),
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

  const stagedPaths = new Set(files.map((file) => file.relativePath));
  const warnings = snapshot.skipped.map(
    (skip) => `${skip.path}: not content-scanned (${skip.reason})`
  );

  const provider = async (file: ProjectFile): Promise<TextFileReadResult> => {
    const oid = oidByPath.get(file.relativePath);
    const read = oid ? blobs.get(oid) : undefined;
    if (!read) {
      throw new ToolipError(
        `Staged content for ${file.relativePath} was not available; refusing to treat the commit as clean.`,
        { code: 'GIT_INDEX_READ_FAILED', exitCode: 1 }
      );
    }
    if (read.status !== 'ok') {
      warnings.push(
        `${file.relativePath}: not content-scanned (${read.status})`
      );
    }
    return read;
  };

  const findings = await analyze(
    context,
    { stagedPaths, provider },
    options.signal
  );
  return summarize(findings, files.length, 'staged', warnings);
}

async function analyze(
  context: ScannerContext,
  staged:
    | {
        stagedPaths: ReadonlySet<string>;
        provider: (file: ProjectFile) => Promise<TextFileReadResult>;
      }
    | undefined,
  signal?: AbortSignal
): Promise<Finding[]> {
  const [doctor, gitAudit] = await Promise.all([
    runSecurityDoctor(context, {
      signal,
      contentProvider: staged?.provider
    }),
    runGitAudit(context)
  ]);
  const combined = [...doctor.findings, ...gitAudit.findings];

  return staged
    ? combined.filter((finding) =>
        findingAppliesToStagedScope(finding, staged.stagedPaths)
      )
    : combined;
}

function summarize(
  findings: Finding[],
  filesConsidered: number,
  scope: 'staged' | 'full',
  warnings: string[]
): PreCommitResult {
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const blocking = critical + high;

  return {
    passed: blocking === 0,
    findings,
    scope,
    filesConsidered,
    warnings,
    summary: { critical, high, blocking }
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
