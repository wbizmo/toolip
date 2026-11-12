import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import path from 'node:path';
import { lstat, open, realpath } from 'node:fs/promises';
import { walkProjectFiles } from '../core/file-walker.js';
import { runGit } from '../core/git/safe-git.js';
import type { ProjectFile } from '../core/file-walker.js';
import {
  freezeScannerContext,
  type ScannerContext
} from '../core/scanner-context.js';
import { profileProject } from '../core/profile-project.js';
import {
  TextFileReader,
  defaultTextFileBudget
} from '../core/text-file-reader.js';
import type {
  FileSnapshot,
  TextFileReadResult
} from '../core/text-file-reader.js';

const snapshotContextIds = new WeakMap<ScannerContext, string>();

/** Immutable, content-addressed input to repeatable analysis. */
export type ProjectSnapshot = Readonly<{
  root: string;
  id: string;
  gitRevision?: string;
  gitHeadRevision?: string;
  gitIndexDigest?: string;
  gitIndexStatus: 'available' | 'not_git' | 'unavailable';
  /** Stable digest of captured path/content identities, independent of host metadata. */
  sourceTreeDigest: string;
  lockGraphDigest?: string;
  configDigest?: string;
  budgets: Readonly<{
    maxFiles: number;
    maxFileBytes: number;
    maxTotalBytes: number;
  }>;
  metrics: Readonly<{
    filesReused: number;
    bytesReused: number;
    filesRead: number;
    bytesRead: number;
  }>;
  files: readonly Readonly<{
    path: string;
    fileId: string;
    mtimeNs: string;
    ctimeNs: string;
    mtimeMs: number;
    ctimeMs: number;
    dev: string;
    ino: string;
    sha256: string;
    bytes: number;
    binary: boolean;
    content?: string;
  }>[];
}>;

export type ProjectSnapshotOptions = {
  signal?: AbortSignal;
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  gitRevision?: string;
  lockGraphDigest?: string;
  configDigest?: string;
  discoveredFiles?: readonly ProjectFile[];
  previous?: ProjectSnapshot;
};

function throwIfSnapshotCancelled(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  const error = new Error('snapshot cancelled');
  error.name = 'AbortError';
  throw error;
}

/** Dependency resolvers consume lockfiles and manifests from the same captured input. */
export function dependencyFileSourceFromSnapshot(snapshot: ProjectSnapshot): {
  files: readonly string[];
  hasFile: (relativePath: string) => boolean;
  readText: (relativePath: string) => string | undefined;
} {
  const contents = new Map(
    snapshot.files.map((file) => [file.path, file.content] as const)
  );
  return Object.freeze({
    files: Object.freeze([...contents.keys()]),
    hasFile: (relativePath: string) => contents.has(relativePath),
    readText: (relativePath: string) => contents.get(relativePath)
  });
}

async function readGitIndexDigest(root: string): Promise<{
  digest?: string;
  revision?: string;
  status: 'available' | 'not_git' | 'unavailable';
}> {
  const [headResult, indexResult] = await Promise.all([
    runGit(['rev-parse', '--verify', 'HEAD^{commit}'], {
      cwd: root,
      timeoutMs: 3_000,
      maxBuffer: 4_096
    }),
    runGit(['rev-parse', '--git-path', 'index'], {
      cwd: root,
      timeoutMs: 3_000,
      maxBuffer: 4_096
    })
  ]).catch(() => [] as never[]);
  if (!headResult || !indexResult) return { status: 'unavailable' };
  if (headResult.code !== 0 && indexResult.code !== 0)
    return { status: 'not_git' };
  if (indexResult.code !== 0) return { status: 'unavailable' };
  const rawRevision = headResult.stdout.toString('utf8').trim();
  const revision = /^[a-f0-9]{40,64}$/iu.test(rawRevision)
    ? rawRevision.toLowerCase()
    : undefined;
  const indexPath = path.resolve(
    root,
    indexResult.stdout.toString('utf8').trim()
  );
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const before = await lstat(indexPath, { bigint: true }).catch(
    () => undefined
  );
  if (!before?.isFile() || before.size > 32n * 1024n * 1024n)
    return { status: 'unavailable' };
  const handle = await open(indexPath, constants.O_RDONLY | noFollow).catch(
    () => undefined
  );
  if (!handle) return { status: 'unavailable' };
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    )
      return { status: 'unavailable' };
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(64 * 1024);
    let offset = 0;
    while (offset < Number(opened.size)) {
      const read = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, Number(opened.size) - offset),
        offset
      );
      if (read.bytesRead <= 0) return { status: 'unavailable' };
      hash.update(buffer.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    const extra = Buffer.alloc(1);
    if ((await handle.read(extra, 0, 1, offset)).bytesRead !== 0)
      return { status: 'unavailable' };
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(indexPath, { bigint: true });
    if (
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size !== after.size ||
      opened.mtimeNs !== after.mtimeNs ||
      opened.ctimeNs !== after.ctimeNs ||
      afterPath.isSymbolicLink() ||
      afterPath.dev !== opened.dev ||
      afterPath.ino !== opened.ino
    )
      return { status: 'unavailable' };
    return {
      digest: hash.digest('hex'),
      revision,
      status: 'available'
    };
  } catch {
    return { status: 'unavailable' };
  } finally {
    await handle.close();
  }
}

/**
 * Captures a deterministic bounded input snapshot. Discovery is O(F log F)
 * because canonical output is sorted; reading and hashing are O(B) time and
 * O(B) peak memory, bounded by the configured aggregate byte budget.
 */
export async function createProjectSnapshot(
  root: string,
  options: ProjectSnapshotOptions = {}
): Promise<ProjectSnapshot> {
  throwIfSnapshotCancelled(options.signal);
  const rootPath = await realpath(path.resolve(root));
  throwIfSnapshotCancelled(options.signal);
  const files = options.discoveredFiles
    ? [...options.discoveredFiles]
    : await walkProjectFiles(rootPath, {
        maxFiles: options.maxFiles,
        signal: options.signal,
        includeTrackedIgnored: true
      });
  const budgets = {
    maxFiles: options.maxFiles ?? defaultTextFileBudget.maxFiles,
    maxFileBytes: options.maxFileBytes ?? defaultTextFileBudget.maxFileBytes,
    maxTotalBytes: options.maxTotalBytes ?? defaultTextFileBudget.maxTotalBytes
  };
  const previousFiles = new Map(
    options.previous?.root === rootPath
      ? options.previous.files.map((file) => [file.path, file])
      : []
  );
  const reusable = new Map<string, ProjectSnapshot['files'][number]>();
  for (const file of files) {
    const prior = previousFiles.get(file.relativePath);
    const stat = file.snapshot;
    if (
      prior &&
      options.previous?.budgets.maxFiles === budgets.maxFiles &&
      options.previous.budgets.maxFileBytes === budgets.maxFileBytes &&
      options.previous.budgets.maxTotalBytes === budgets.maxTotalBytes &&
      stat &&
      prior.fileId === `${stat.dev}:${stat.ino}` &&
      prior.mtimeNs === String(stat.mtimeNs) &&
      prior.ctimeNs === String(stat.ctimeNs) &&
      prior.bytes === stat.size
    ) {
      reusable.set(file.relativePath, prior);
    }
  }
  const reusedBytes = [...reusable.values()].reduce(
    (total, file) => total + file.bytes,
    0
  );
  if (reusable.size > budgets.maxFiles || reusedBytes > budgets.maxTotalBytes)
    throw new Error('snapshot reuse exceeds the configured project budget');
  const reader = new TextFileReader(
    {
      maxFiles: budgets.maxFiles - reusable.size,
      maxFileBytes: budgets.maxFileBytes,
      maxTotalBytes: budgets.maxTotalBytes - reusedBytes
    },
    { root: rootPath }
  );
  const content: Array<{
    path: string;
    fileId: string;
    mtimeNs: string;
    ctimeNs: string;
    mtimeMs: number;
    ctimeMs: number;
    dev: string;
    ino: string;
    sha256: string;
    bytes: number;
    binary: boolean;
    content?: string;
  }> = [];
  for (const file of files) {
    throwIfSnapshotCancelled(options.signal);
    const prior = reusable.get(file.relativePath);
    if (prior) {
      content.push(prior);
      continue;
    }
    const read = await reader.read(
      file.absolutePath,
      options.signal,
      file.snapshot
    );
    if (read.status !== 'ok' && read.status !== 'binary') {
      throw new Error(
        `snapshot incomplete for ${file.relativePath}: ${read.status}`
      );
    }
    if (!read.sha256 || !read.snapshot) {
      throw new Error(
        `snapshot incomplete for ${file.relativePath}: missing read identity`
      );
    }
    content.push(
      Object.freeze({
        path: file.relativePath,
        fileId: `${read.snapshot.dev}:${read.snapshot.ino}`,
        mtimeNs: String(read.snapshot.mtimeNs),
        ctimeNs: String(read.snapshot.ctimeNs),
        mtimeMs: read.snapshot.mtimeMs,
        ctimeMs: read.snapshot.ctimeMs,
        dev: String(read.snapshot.dev),
        ino: String(read.snapshot.ino),
        sha256: read.sha256,
        bytes: read.bytes,
        binary: read.status === 'binary',
        ...(read.status === 'ok' ? { content: read.content } : {})
      })
    );
  }
  const lockGraphDigest =
    options.lockGraphDigest ??
    createHash('sha256')
      .update(
        JSON.stringify(
          content
            .filter((file) =>
              /(?:^|\/)(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|\.npmrc|pnpm-lock\.yaml|pnpm-workspace\.yaml|yarn\.lock|\.yarnrc(?:\.yml)?|Cargo\.toml|Cargo\.lock|go\.mod|go\.sum|go\.work(?:\.sum)?|composer\.json|composer\.lock|Pipfile(?:\.lock)?|pyproject\.toml|poetry\.lock|uv\.lock|requirements(?:-[^/]+)?\.txt|pom\.xml|gradle\.lockfile|gradle\.properties|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?)$/iu.test(
                file.path
              )
            )
            .map((file) => [file.path, file.sha256])
            .sort((left, right) =>
              String(left[0]).localeCompare(String(right[0]))
            )
        )
      )
      .digest('hex');
  const sourceTreeDigest = createHash('sha256')
    .update('toolip-source-snapshot-v1\0')
    .update(String(content.length))
    .update('\0');
  const sourceFiles = [...content].sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0
  );
  for (const file of sourceFiles) {
    sourceTreeDigest
      .update(String(Buffer.byteLength(file.path, 'utf8')))
      .update(':')
      .update(file.path)
      .update('\0')
      .update(String(file.bytes))
      .update('\0')
      .update(file.binary ? 'binary' : 'text')
      .update('\0')
      .update(file.sha256)
      .update('\0');
  }
  const sourceTreeDigestHex = sourceTreeDigest.digest('hex');
  const configDigest =
    options.configDigest ??
    createHash('sha256')
      .update(
        JSON.stringify(
          content
            .filter(
              (file) =>
                file.path.startsWith('.toolip/') ||
                file.path === 'toolip.config.json' ||
                file.path === '.tooliprc'
            )
            .map((file) => [file.path, file.sha256])
            .sort((left, right) =>
              String(left[0]).localeCompare(String(right[0]))
            )
        )
      )
      .digest('hex');
  const git = await readGitIndexDigest(rootPath);
  const gitRevision = options.gitRevision ?? git.revision;
  const gitIndexDigest = git.digest;
  const digest = createHash('sha256')
    .update(
      JSON.stringify({
        root: rootPath,
        gitRevision: gitRevision ?? null,
        gitHeadRevision: git.revision ?? null,
        gitIndexDigest: gitIndexDigest ?? null,
        gitIndexStatus: git.status,
        sourceTreeDigest: sourceTreeDigestHex,
        lockGraphDigest,
        configDigest,
        budget: budgets,
        files: content.map(
          ({
            path: filePath,
            fileId,
            mtimeNs,
            ctimeNs,
            mtimeMs,
            ctimeMs,
            dev,
            ino,
            sha256,
            bytes,
            binary
          }) => [
            filePath,
            fileId,
            mtimeNs,
            ctimeNs,
            mtimeMs,
            ctimeMs,
            dev,
            ino,
            sha256,
            bytes,
            binary
          ]
        )
      })
    )
    .digest('hex');
  return Object.freeze({
    root: rootPath,
    id: digest,
    ...(gitRevision ? { gitRevision } : {}),
    ...(git.revision ? { gitHeadRevision: git.revision } : {}),
    ...(gitIndexDigest ? { gitIndexDigest } : {}),
    gitIndexStatus: git.status,
    sourceTreeDigest: sourceTreeDigestHex,
    ...(lockGraphDigest ? { lockGraphDigest } : {}),
    ...(configDigest ? { configDigest } : {}),
    budgets: Object.freeze(budgets),
    metrics: Object.freeze({
      filesReused: reusable.size,
      bytesReused: reusedBytes,
      filesRead: reader.usage.filesRead,
      bytesRead: reader.usage.bytesRead
    }),
    files: Object.freeze(content)
  });
}

/** Verifies that a snapshot's files still match current bytes before use. */
export async function verifyProjectSnapshot(
  snapshot: ProjectSnapshot,
  options: { signal?: AbortSignal } = {}
): Promise<boolean> {
  throwIfSnapshotCancelled(options.signal);
  const root = await realpath(snapshot.root).catch(() => undefined);
  throwIfSnapshotCancelled(options.signal);
  if (!root) return false;
  throwIfSnapshotCancelled(options.signal);
  const git = await readGitIndexDigest(root);
  if (
    git.status !== snapshot.gitIndexStatus ||
    git.digest !== snapshot.gitIndexDigest ||
    git.revision !== snapshot.gitHeadRevision
  )
    return false;
  let discovered: ProjectFile[];
  try {
    discovered = await walkProjectFiles(root, {
      maxFiles: Math.max(1, snapshot.files.length),
      signal: options.signal,
      includeTrackedIgnored: true
    });
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error;
    return false;
  }
  if (discovered.length !== snapshot.files.length) return false;
  const discoveredByPath = new Map(
    discovered.map((file) => [file.relativePath, file])
  );
  const bytesTotal = snapshot.files.reduce(
    (total, file) => total + file.bytes,
    0
  );
  const reader = new TextFileReader(
    {
      maxFiles: Math.max(1, snapshot.files.length),
      maxFileBytes: Math.max(
        1,
        snapshot.files.reduce(
          (maximum, file) => Math.max(maximum, file.bytes),
          0
        )
      ),
      maxTotalBytes: bytesTotal
    },
    { root }
  );
  for (const file of snapshot.files) {
    throwIfSnapshotCancelled(options.signal);
    try {
      const discoveredFile = discoveredByPath.get(file.path);
      if (
        !discoveredFile ||
        `${discoveredFile.snapshot?.dev}:${discoveredFile.snapshot?.ino}` !==
          file.fileId ||
        String(discoveredFile.snapshot?.mtimeNs) !== file.mtimeNs ||
        String(discoveredFile.snapshot?.ctimeNs) !== file.ctimeNs
      )
        return false;
      const read = await reader.read(
        path.join(root, file.path),
        options.signal,
        discoveredFile.snapshot
      );
      if (read.status === 'cancelled') throwIfSnapshotCancelled(options.signal);
      if (file.binary) {
        if (
          read.status !== 'binary' ||
          read.bytes !== file.bytes ||
          read.sha256 !== file.sha256
        )
          return false;
      } else if (
        read.status !== 'ok' ||
        read.bytes !== file.bytes ||
        read.sha256 !== file.sha256
      ) {
        return false;
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') throw error;
      return false;
    }
  }
  return true;
}

function toFileSnapshot(file: ProjectSnapshot['files'][number]): FileSnapshot {
  return {
    dev: BigInt(file.dev),
    ino: BigInt(file.ino),
    size: file.bytes,
    mtimeMs: file.mtimeMs,
    ctimeMs: file.ctimeMs,
    mtimeNs: BigInt(file.mtimeNs),
    ctimeNs: BigInt(file.ctimeNs)
  };
}

/** Returns captured text/metadata and never reads the current worktree. */
export function snapshotContentProvider(
  snapshot: ProjectSnapshot
): (file: ProjectFile) => Promise<TextFileReadResult> {
  const files = new Map(snapshot.files.map((file) => [file.path, file]));
  return async (projectFile) => {
    const captured = files.get(projectFile.relativePath);
    if (!captured) {
      return {
        status: 'failed',
        bytes: 0,
        error: 'file was not part of the immutable project snapshot'
      };
    }
    const fileSnapshot = toFileSnapshot(captured);
    return captured.binary
      ? {
          status: 'binary',
          bytes: captured.bytes,
          sha256: captured.sha256,
          snapshot: fileSnapshot
        }
      : {
          status: 'ok',
          content: captured.content ?? '',
          bytes: captured.bytes,
          sha256: captured.sha256,
          snapshot: fileSnapshot
        };
  };
}

/** Builds the shared scanner context from captured paths and captured content. */
export async function scannerContextFromSnapshot(
  snapshot: ProjectSnapshot
): Promise<ScannerContext> {
  const files: ProjectFile[] = snapshot.files.map((file) => ({
    absolutePath: path.join(snapshot.root, file.path),
    relativePath: file.path,
    extension: path.extname(file.path).replace(/^\./u, '').toLowerCase(),
    snapshot: toFileSnapshot(file)
  }));
  const contents = new Map(
    snapshot.files.flatMap((file) =>
      file.binary || file.content === undefined
        ? []
        : [[file.path, file.content] as const]
    )
  );
  const profile = await profileProject(snapshot.root, files, {
    snapshotContents: contents
  });
  const extensions = files.reduce<Record<string, number>>((summary, file) => {
    const extension = file.extension || 'none';
    summary[extension] = (summary[extension] ?? 0) + 1;
    return summary;
  }, {});
  const context = freezeScannerContext({
    root: snapshot.root,
    profile,
    files,
    summary: {
      totalFiles: files.length,
      extensions
    }
  });
  snapshotContextIds.set(context, snapshot.id);
  return context;
}

/** True only for the immutable context constructed from this exact snapshot. */
export function isScannerContextFromSnapshot(
  context: ScannerContext,
  snapshot: ProjectSnapshot
): boolean {
  return snapshotContextIds.get(context) === snapshot.id;
}
