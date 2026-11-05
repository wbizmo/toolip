import { spawn } from 'node:child_process';
import { ToolipError } from '../../errors/toolip-error.js';
import {
  defaultTextFileBudget,
  type TextFileBudget,
  type TextFileReadResult
} from '../text-file-reader.js';
import { runGit } from './safe-git.js';

export type StagedEntry = {
  /** Path relative to the scanned root, forward slashes. */
  path: string;
  mode: string;
  /** Object ID of the staged blob (what will actually be committed). */
  oid: string;
};

export type StagedSkip = { path: string; reason: string };

export type StagedSnapshot = {
  entries: StagedEntry[];
  skipped: StagedSkip[];
};

/**
 * Enumerates what the index would commit: additions, modifications and type
 * changes against HEAD (deletions need no scan). NUL-delimited raw diff output
 * handles spaces, newlines and non-ASCII names; renames are reported as a
 * delete plus an add so the new path is scanned. Submodules and symlinks are
 * recorded as skipped. Unmerged entries fail closed.
 * Complexity: O(S) for S staged paths in time and space.
 */
export async function listStagedEntries(
  root: string,
  signal?: AbortSignal
): Promise<StagedSnapshot> {
  const result = await runGit(
    [
      'diff',
      '--cached',
      '--raw',
      '-z',
      '--no-abbrev',
      '--no-renames',
      '--no-ext-diff',
      '--no-textconv',
      '--relative',
      '--'
    ],
    { cwd: root, maxBuffer: 64 * 1024 * 1024, signal }
  );

  if (result.code !== 0) {
    throw new ToolipError(
      'Pre-commit staged scanning requires a Git working tree. Use --full only for an explicit repository-wide manual check.',
      { code: 'PRE_COMMIT_GIT_REQUIRED', exitCode: 1 }
    );
  }

  const tokens = result.stdout.toString('utf8').split('\0');
  const entries: StagedEntry[] = [];
  const skipped: StagedSkip[] = [];
  const unmerged: string[] = [];

  for (let i = 0; i + 1 < tokens.length; i += 2) {
    const header = tokens[i] ?? '';
    const filePath = (tokens[i + 1] ?? '').replaceAll('\\', '/');
    const match = /^:(\d{6}) (\d{6}) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])\d*$/u.exec(
      header
    );

    if (!match || filePath.length === 0) {
      throw new ToolipError(
        'Could not parse the Git index listing; refusing to treat the commit as clean.',
        { code: 'GIT_INDEX_READ_FAILED', exitCode: 1 }
      );
    }

    const [, , newMode, , newOid, status] = match as unknown as [
      string,
      string,
      string,
      string,
      string,
      string
    ];

    if (status === 'D') continue;
    if (status === 'U') {
      unmerged.push(filePath);
      continue;
    }
    if (newMode === '160000') {
      skipped.push({ path: filePath, reason: 'submodule (gitlink)' });
      continue;
    }
    if (newMode === '120000') {
      skipped.push({ path: filePath, reason: 'symbolic link' });
      continue;
    }

    entries.push({ path: filePath, mode: newMode, oid: newOid });
  }

  if (unmerged.length > 0) {
    throw new ToolipError(
      `The index has unmerged paths (${unmerged.slice(0, 5).join(', ')}${unmerged.length > 5 ? ', …' : ''}). Resolve the conflicts before committing.`,
      { code: 'PRE_COMMIT_UNMERGED_PATHS', exitCode: 1 }
    );
  }

  return { entries, skipped };
}

/**
 * Reads staged blobs by object ID through ONE `git cat-file --batch` process.
 * The worktree is never opened, so partial staging, deleted or renamed
 * worktree files and path tricks cannot change what is scanned. Any Git
 * failure, missing object or malformed stream rejects (fail closed).
 *
 * Memory is bounded by the budget: oversized blobs are drained without being
 * retained, and retained bytes never exceed maxTotalBytes.
 * Complexity: O(B) in blob bytes read; space O(min(B, maxTotalBytes)).
 */
export async function readBlobs(
  root: string,
  oids: readonly string[],
  budget: TextFileBudget = defaultTextFileBudget,
  signal?: AbortSignal
): Promise<Map<string, TextFileReadResult>> {
  const unique = [...new Set(oids)];
  const results = new Map<string, TextFileReadResult>();
  if (unique.length === 0) return results;

  for (const oid of unique) {
    if (!/^[0-9a-f]{40,64}$/u.test(oid)) {
      throw new ToolipError('Invalid object ID in the Git index listing.', {
        code: 'GIT_INDEX_READ_FAILED',
        exitCode: 1
      });
    }
  }

  await new Promise<void>((resolve, reject) => {
    const child = spawn('git', ['cat-file', '--batch'], {
      cwd: root,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' }
    });

    // Reject only after the child has exited so no `git cat-file` process
    // outlives the call (a lingering child keeps its cwd locked on Windows).
    let failure: ToolipError | undefined;
    let exited = false;
    const fail = (message: string) => {
      failure ??= new ToolipError(message, {
        code: 'GIT_INDEX_READ_FAILED',
        exitCode: 1
      });
      if (exited) {
        reject(failure);
        return;
      }
      child.kill();
    };

    let pending: Buffer = Buffer.alloc(0);
    let index = 0;
    let retained = 0;
    let filesRead = 0;
    let expect: {
      oid: string;
      size: number;
      kept: Buffer[];
      got: number;
      keep: boolean;
    } | null = null;
    let stderr = '';

    const onAbort = () => fail('Git index read was cancelled.');
    signal?.addEventListener('abort', onAbort, { once: true });

    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < 2000) stderr += chunk.toString('utf8');
    });
    child.on('error', () => {
      // 'close' may never fire when spawn itself failed.
      exited = true;
      fail('Git is required but could not be started.');
    });

    child.stdout.on('data', (chunk: Buffer) => {
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);

      for (;;) {
        if (!expect) {
          const newline = pending.indexOf(0x0a);
          if (newline === -1) return;
          const header = pending.subarray(0, newline).toString('utf8');
          pending = pending.subarray(newline + 1);
          const oid = unique[index];
          const parts = header.split(' ');

          if (
            oid === undefined ||
            parts[0] !== oid ||
            parts[1] !== 'blob' ||
            !/^\d+$/u.test(parts[2] ?? '')
          ) {
            fail(
              `Git could not provide staged blob ${oid ?? '?'} (${header.slice(0, 80)}).`
            );
            return;
          }

          const size = Number(parts[2]);
          const keep =
            size <= budget.maxFileBytes &&
            retained + size <= budget.maxTotalBytes &&
            filesRead < budget.maxFiles;
          if (!keep) {
            results.set(oid, {
              status:
                size > budget.maxFileBytes ? 'oversized' : 'budget-exceeded',
              bytes: size
            });
          }
          expect = { oid, size, kept: [], got: 0, keep };
          if (keep) {
            retained += size;
            filesRead += 1;
          }
        }

        // Body is `size` bytes followed by one LF.
        const needed = expect.size + 1 - expect.got;
        if (pending.length === 0) return;
        const take = Math.min(needed, pending.length);
        if (expect.keep) expect.kept.push(pending.subarray(0, take));
        expect.got += take;
        pending = pending.subarray(take);

        if (expect.got < expect.size + 1) return;

        if (expect.keep) {
          const body = Buffer.concat(expect.kept).subarray(0, expect.size);
          const sample = body.subarray(0, 8 * 1024);
          results.set(
            expect.oid,
            sample.includes(0)
              ? { status: 'binary', bytes: expect.size }
              : {
                  status: 'ok',
                  content: body.toString('utf8'),
                  bytes: expect.size
                }
          );
        }
        expect = null;
        index += 1;
      }
    });

    child.on('close', (code) => {
      exited = true;
      signal?.removeEventListener('abort', onAbort);
      if (failure) {
        reject(failure);
        return;
      }
      if (code !== 0 || index !== unique.length || expect) {
        reject(
          new ToolipError(
            `Reading staged content from Git failed${stderr ? `: ${stderr.trim().split('\n')[0]?.slice(0, 160)}` : ''}. Refusing to treat the commit as clean.`,
            { code: 'GIT_INDEX_READ_FAILED', exitCode: 1 }
          )
        );
        return;
      }
      resolve();
    });

    child.stdin.on('error', () => undefined);
    child.stdin.end(`${unique.join('\n')}\n`);
  });

  return results;
}

/** Used by tests/diagnostics: confirms the directory is inside a work tree. */
export async function isInsideWorkTree(root: string): Promise<boolean> {
  const result = await runGit(['rev-parse', '--is-inside-work-tree'], {
    cwd: root,
    timeoutMs: 10_000,
    maxBuffer: 1024
  });
  return result.code === 0 && result.stdout.toString('utf8').trim() === 'true';
}
