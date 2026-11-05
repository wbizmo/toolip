import path from 'node:path';
import { gatedFindings, type FailOn } from '../application/analysis-status.js';
import type { AnalysisCoverage } from '../contracts/analysis.js';
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
import { runSecurityDoctor, shouldScanSecrets } from './security-doctor.js';
import {
  defaultTextFileBudget,
  type TextFileReadResult
} from './text-file-reader.js';

export type PreCommitOptions = {
  full?: boolean;
  signal?: AbortSignal;
  /** Severity at or above which findings block. Default `high` (critical + high). */
  failOn?: FailOn;
  /**
   * Fail closed when eligible inputs were not analyzed (oversized, unreadable,
   * binary, cancelled). Staged scans always enforce this; only explicit
   * full-repository scans may opt out of partial coverage.
   */
  failOnIncomplete?: boolean;
};

export type PreCommitResult = {
  passed: boolean;
  findings: Finding[];
  scope: 'staged' | 'full';
  filesConsidered: number;
  /** What the secret/config scan actually examined. */
  coverage: AnalysisCoverage;
  /** True when the commit was rejected only because coverage was incomplete. */
  blockedByIncompleteScan: boolean;
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
    const analysis = await analyze(context, undefined, options.signal);
    return summarize(analysis, context.files.length, 'full', [], options);
  }

  const absoluteRoot = path.resolve(root);
  const snapshot = await listStagedEntries(absoluteRoot, options.signal);
  const toolipIgnore = await loadToolipIgnore(absoluteRoot);
  const entries = snapshot.entries.filter(
    (entry) => !toolipIgnore.ignores(path.join(absoluteRoot, entry.path))
  );
  const blobs = await readBlobs(
    absoluteRoot,
    // Only blobs the secret scan will open: assets and build output must not
    // consume the byte/file budget and starve eligible files into warnings.
    entries
      .filter((entry) =>
        shouldScanSecrets(
          entry.path,
          path.extname(entry.path).replace('.', '').toLowerCase()
        )
      )
      .map((entry) => entry.oid),
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

  const analysis = await analyze(
    context,
    { stagedPaths, provider },
    options.signal
  );
  return summarize(analysis, files.length, 'staged', warnings, options);
}

type Analysis = { findings: Finding[]; coverage: AnalysisCoverage };

async function analyze(
  context: ScannerContext,
  staged:
    | {
        stagedPaths: ReadonlySet<string>;
        provider: (file: ProjectFile) => Promise<TextFileReadResult>;
      }
    | undefined,
  signal?: AbortSignal
): Promise<Analysis> {
  const [doctor, gitAudit] = await Promise.all([
    runSecurityDoctor(context, {
      signal,
      contentProvider: staged?.provider
    }),
    runGitAudit(context)
  ]);
  const combined = [...doctor.findings, ...gitAudit.findings];

  return {
    findings: staged
      ? combined.filter((finding) =>
          findingAppliesToStagedScope(finding, staged.stagedPaths)
        )
      : combined,
    coverage: doctor.coverage
  };
}

function summarize(
  analysis: Analysis,
  filesConsidered: number,
  scope: 'staged' | 'full',
  warnings: string[],
  options: PreCommitOptions
): PreCommitResult {
  const { findings, coverage } = analysis;
  const threshold: FailOn = options.failOn ?? 'high';
  const blockingFindings = gatedFindings(findings, threshold);
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const failOnIncomplete =
    scope === 'staged' || (options.failOnIncomplete ?? true);
  // The opt-out tolerates SOME unexamined files (partial). A scan in which no
  // eligible input could be examined (failed) always blocks: nothing was verified.
  const incompleteBlocks =
    coverage.state === 'failed' ||
    (coverage.state === 'partial' && failOnIncomplete);
  const blockedByIncompleteScan =
    incompleteBlocks && blockingFindings.length === 0;

  return {
    // A partial scan is not an all-clear: unreadable, oversized or otherwise
    // unexamined eligible inputs block unless the caller explicitly opts out.
    passed: blockingFindings.length === 0 && !incompleteBlocks,
    findings,
    scope,
    filesConsidered,
    coverage,
    blockedByIncompleteScan,
    warnings,
    summary: { critical, high, blocking: blockingFindings.length }
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
