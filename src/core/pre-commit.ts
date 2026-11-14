import path from 'node:path';
import { gatedFindings, type FailOn } from '../application/analysis-status.js';
import type { AnalysisCoverage } from '../contracts/analysis.js';
import type { Finding } from '../contracts/finding.js';
import { ToolipError } from '../errors/toolip-error.js';
import { runGitAudit } from './git-audit.js';
import {
  listIndexEntries,
  listStagedEntries,
  readBlobs
} from './git/staged-index.js';
import type { ProjectFile } from './file-walker.js';
import { profileProject } from './profile-project.js';
import {
  createScannerContext,
  type ScannerContext
} from './scanner-context.js';
import { runSecurityDoctor, shouldScanSecrets } from './security-doctor.js';
import { shouldInspectMaliciousContent } from '../analyzers/malicious-content/analyzer.js';
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
 * Staged mode reads its selected content from index blobs and, for malicious
 * execution-chain analysis, uses a bounded read of the complete stage-0 index
 * so unchanged reachable targets are not mistaken for missing files. Its
 * complexity is O(I + B) for I indexed paths and B retained blob bytes (both
 * bounded); the worktree is not walked.
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
  // Staged content is already an explicit user selection. Repository ignore
  // files must not hide a tracked or staged security-relevant file.
  const entries = snapshot.entries;
  const index = await listIndexEntries(absoluteRoot, options.signal);
  const indexEntryByPath = new Map(
    index.entries.map((entry) => [entry.path, entry])
  );
  const stagedPaths = new Set(entries.map((entry) => entry.path));
  const maliciousContentFiles: ProjectFile[] = index.entries
    .filter((entry) =>
      shouldInspectMaliciousContent(
        entry.path,
        path.extname(entry.path).replace('.', '').toLowerCase()
      )
    )
    .map((entry) => ({
      absolutePath: path.join(absoluteRoot, entry.path),
      relativePath: entry.path,
      extension: path.extname(entry.path).replace('.', '').toLowerCase()
    }));
  const blobs = await readBlobs(
    absoluteRoot,
    // Read the staged inputs and the bounded indexed content needed to trace
    // unchanged targets from staged execution entrypoints. Known binary assets
    // and source maps remain excluded from the content budget.
    index.entries
      .filter((entry) => {
        const extension = path
          .extname(entry.path)
          .replace('.', '')
          .toLowerCase();
        return (
          (stagedPaths.has(entry.path) &&
            shouldScanSecrets(entry.path, extension)) ||
          shouldInspectMaliciousContent(entry.path, extension)
        );
      })
      .map((entry) => entry.oid),
    defaultTextFileBudget,
    options.signal
  );
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

  const warnings = snapshot.skipped.map(
    (skip) => `${skip.path}: not content-scanned (${skip.reason})`
  );

  const provider = async (file: ProjectFile): Promise<TextFileReadResult> => {
    const indexEntry = indexEntryByPath.get(file.relativePath);
    const read = indexEntry ? blobs.get(indexEntry.oid) : undefined;
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
    { stagedPaths, provider, maliciousContentFiles },
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
        maliciousContentFiles: readonly ProjectFile[];
      }
    | undefined,
  signal?: AbortSignal
): Promise<Analysis> {
  const [doctor, gitAudit] = await Promise.all([
    runSecurityDoctor(context, {
      signal,
      contentProvider: staged?.provider,
      ...(staged ? { maliciousContentFiles: staged.maliciousContentFiles } : {})
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
    if (staged.has(normalizePath(finding.location.file))) return true;
  }
  if (finding.category === 'malicious-content') {
    const trace = finding.metadata?.trace;
    if (
      Array.isArray(trace) &&
      trace.some(
        (file): file is string =>
          typeof file === 'string' && staged.has(normalizePath(file))
      )
    )
      return true;
  }

  return finding.category === 'git-security' && staged.has('.gitignore');
}

function normalizePath(value: string): string {
  return value.replaceAll('\\', '/').replace(/^\.\//, '');
}
