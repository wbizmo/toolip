import path from 'node:path';
import { lstat, realpath, stat as statTarget } from 'node:fs/promises';
import fg from 'fast-glob';
import { mapConcurrent } from '../application/concurrency.js';
import { ToolipError } from '../errors/toolip-error.js';
import { loadToolipIgnore, type ToolipIgnore } from './load-toolip-ignore.js';
import { runGit } from './git/safe-git.js';
import { snapshotOf, type FileSnapshot } from './text-file-reader.js';

export type ProjectFile = {
  absolutePath: string;
  relativePath: string;
  extension: string;
  snapshot?: FileSnapshot;
};

export type FileWalkOptions = {
  maxFiles?: number;
  signal?: AbortSignal;
  findEntries?: (root: string, ignorePatterns: string[]) => Promise<string[]>;
  lstatEntry?: typeof lstat;
  statTarget?: typeof statTarget;
  /** Include present index-tracked files even when local ignore rules match. */
  includeTrackedIgnored?: boolean;
};

const metadataConcurrency = 32;
const defaultMaxFiles = 50_000;

type StreamEntry = {
  path: string;
  dirent: {
    isFile: () => boolean;
    isSymbolicLink: () => boolean;
  };
};

async function trackedEntries(
  root: string,
  signal?: AbortSignal
): Promise<string[]> {
  let ancestor = root;
  let hasGitMarker = false;
  while (true) {
    try {
      await lstat(path.join(ancestor, '.git'));
      hasGitMarker = true;
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new ToolipError('Project Git metadata could not be inspected.', {
          code: 'SCAN_DISCOVERY_INCOMPLETE'
        });
      }
      const parent = path.dirname(ancestor);
      if (parent === ancestor) break;
      ancestor = parent;
    }
  }
  if (
    !hasGitMarker &&
    !process.env.GIT_DIR &&
    !process.env.GIT_WORK_TREE &&
    !process.env.GIT_INDEX_FILE
  )
    return [];
  const listing = await runGit(['ls-files', '--cached', '--full-name', '-z'], {
    cwd: root,
    timeoutMs: 5_000,
    maxBuffer: 64 * 1024 * 1024,
    signal
  });
  if (listing.code !== 0) {
    if (
      /not a git repository|not inside a work tree|outside a work tree/iu.test(
        listing.stderr
      )
    )
      return [];
    throw new ToolipError('Git could not list tracked project files.', {
      code: 'SCAN_DISCOVERY_INCOMPLETE'
    });
  }
  const prefixResult = await runGit(['rev-parse', '--show-prefix'], {
    cwd: root,
    timeoutMs: 5_000,
    maxBuffer: 4_096,
    signal
  });
  if (prefixResult.code !== 0)
    throw new ToolipError('Git could not identify the project subdirectory.', {
      code: 'SCAN_DISCOVERY_INCOMPLETE'
    });
  const prefix = prefixResult.stdout.toString('utf8').trim();
  const listedPaths = listing.stdout.toString('utf8');
  if (!Buffer.from(listedPaths, 'utf8').equals(listing.stdout)) {
    throw new ToolipError('Git returned a non-UTF-8 tracked project path.', {
      code: 'SCAN_DISCOVERY_INCOMPLETE'
    });
  }
  const entries: string[] = [];
  for (const raw of listedPaths.split('\0')) {
    if (!raw) continue;
    if (raw.includes('\\')) {
      throw new ToolipError('Git returned an unsupported tracked path.', {
        code: 'SCAN_DISCOVERY_INCOMPLETE'
      });
    }
    const gitPath = raw;
    if (prefix && !gitPath.startsWith(prefix)) continue;
    const relative = prefix ? gitPath.slice(prefix.length) : gitPath;
    const normalized = path.posix.normalize(relative);
    if (
      !normalized ||
      normalized === '.' ||
      normalized === '..' ||
      normalized.startsWith('../') ||
      path.posix.isAbsolute(normalized)
    )
      throw new ToolipError('Git returned an unsafe tracked project path.', {
        code: 'SCAN_DISCOVERY_INCOMPLETE'
      });
    entries.push(normalized);
  }
  return entries;
}

/** Removes ordinary ignored paths before scheduling metadata inspection. */
export function filterIgnoredEntries(
  entries: string[],
  root: string,
  toolipIgnore: ToolipIgnore
): string[] {
  return entries.filter(
    (entry) => !toolipIgnore.ignores(path.join(root, entry))
  );
}

/** Discovers eligible project files with bounded, snapshot-aware metadata reads. */
export async function walkProjectFiles(
  root: string,
  options: FileWalkOptions = {}
): Promise<ProjectFile[]> {
  throwIfCancelled(options.signal);
  const absoluteRoot = await realpath(path.resolve(root));
  throwIfCancelled(options.signal);
  const toolipIgnore = await loadToolipIgnore(absoluteRoot);
  const inspectEntry = options.lstatEntry ?? lstat;
  const resolveTargetStat = options.statTarget ?? statTarget;

  const maxFiles = options.maxFiles ?? defaultMaxFiles;
  let candidates: string[];
  if (options.findEntries) {
    const entries = await options.findEntries(
      absoluteRoot,
      toolipIgnore.patterns
    );
    candidates = filterIgnoredEntries(entries, absoluteRoot, toolipIgnore);
    if (candidates.length > maxFiles) {
      throw fileLimitError(candidates.length, maxFiles);
    }
  } else {
    candidates = [];
    const stream = fg.stream(['**/*'], {
      cwd: absoluteRoot,
      dot: true,
      onlyFiles: false,
      objectMode: true,
      unique: true,
      followSymbolicLinks: false,
      ignore: toolipIgnore.patterns
    }) as unknown as AsyncIterable<string | StreamEntry> & {
      destroy?: () => void;
    };
    const cancelStream = (): void => stream.destroy?.();
    options.signal?.addEventListener('abort', cancelStream, { once: true });
    try {
      for await (const item of stream) {
        throwIfCancelled(options.signal);
        const entry = typeof item === 'string' ? item : item.path;
        if (toolipIgnore.ignores(path.join(absoluteRoot, entry))) continue;
        if (
          typeof item !== 'string' &&
          !item.dirent.isFile() &&
          !item.dirent.isSymbolicLink()
        ) {
          continue;
        }
        candidates.push(entry);
        if (candidates.length > maxFiles) {
          stream.destroy?.();
          throw fileLimitError(candidates.length, maxFiles);
        }
      }
    } finally {
      options.signal?.removeEventListener('abort', cancelStream);
    }
  }
  const tracked = options.includeTrackedIgnored
    ? await trackedEntries(absoluteRoot, options.signal)
    : [];
  const trackedSet = new Set(tracked);
  if (tracked.length > 0) {
    candidates = [...new Set([...candidates, ...tracked])];
    if (candidates.length > maxFiles) {
      throw fileLimitError(candidates.length, maxFiles);
    }
  }
  const files = await mapConcurrent(
    candidates,
    metadataConcurrency,
    async (entry) => {
      const absolutePath = path.join(absoluteRoot, entry);
      const fromRoot = path.relative(absoluteRoot, absolutePath);
      if (
        fromRoot === '..' ||
        fromRoot.startsWith(`..${path.sep}`) ||
        path.isAbsolute(fromRoot)
      ) {
        throw new ToolipError(
          `Project discovery encountered an unsafe relative path: ${entry}`,
          { code: 'SCAN_DISCOVERY_INCOMPLETE' }
        );
      }
      try {
        const stat = await inspectEntry(absolutePath, { bigint: true });
        let isDirectory = stat.isDirectory();
        if (stat.isSymbolicLink()) {
          isDirectory = (await resolveTargetStat(absolutePath)).isDirectory();
          if (isDirectory) {
            if (
              !trackedSet.has(entry) &&
              toolipIgnore.ignores(absolutePath, true)
            )
              return undefined;
            throw new ToolipError(
              `Project discovery encountered a symbolic directory at ${entry}; traversal is incomplete.`,
              { code: 'SCAN_DISCOVERY_INCOMPLETE' }
            );
          }
        }
        if (
          !trackedSet.has(entry) &&
          toolipIgnore.ignores(absolutePath, isDirectory)
        )
          return undefined;
        if (isDirectory) return undefined;
        if (!stat.isFile() && !stat.isSymbolicLink()) return undefined;
        return {
          absolutePath,
          relativePath: entry.replaceAll('\\', '/'),
          extension: path.extname(entry).replace('.', '').toLowerCase(),
          snapshot: snapshotOf(stat)
        } satisfies ProjectFile;
      } catch (error) {
        throw new ToolipError(
          `Project discovery could not inspect ${entry}: ${error instanceof Error ? error.message : String(error)}`,
          { code: 'SCAN_DISCOVERY_INCOMPLETE' }
        );
      }
    },
    options.signal
  );

  const discovered = files
    .flatMap((file) => (file === undefined ? [] : [file]))
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  if (discovered.length > maxFiles) {
    throw fileLimitError(discovered.length, maxFiles);
  }
  return discovered;
}

function throwIfCancelled(signal?: AbortSignal): void {
  if (signal?.aborted)
    throw new ToolipError('Project discovery was cancelled.', {
      code: 'SCAN_CANCELLED'
    });
}

function fileLimitError(discovered: number, maxFiles: number): ToolipError {
  return new ToolipError(
    `Project discovery found at least ${discovered} file entries, above the configured limit of ${maxFiles}. Refine .toolipignore or raise the scan budget explicitly.`,
    { code: 'SCAN_FILE_LIMIT_EXCEEDED' }
  );
}
