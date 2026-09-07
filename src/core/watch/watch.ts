import {
  readdirSync,
  realpathSync,
  statSync,
  watch,
  type FSWatcher
} from 'node:fs';
import path from 'node:path';

export type WatchOptions = {
  debounceMs?: number;
  ignored?: RegExp[];
  onError?: (error: unknown) => void;
};

export function watchProject(
  root: string,
  onChange: () => Promise<void>,
  options: WatchOptions = {}
): () => void {
  const absoluteRoot = canonicalWatchPath(root);
  const debounceMs = options.debounceMs ?? 500;
  const ignored = options.ignored ?? [
    /(^|\/)node_modules(\/|$)/,
    /(^|\/)\.git(\/|$)/,
    /(^|\/)dist(\/|$)/,
    /(^|\/)\.toolip-report(\/|$)/
  ];

  let timer: NodeJS.Timeout | undefined;
  let running = false;
  let queued = false;
  let closed = false;

  const reportError = (error: unknown): void => {
    try {
      options.onError?.(error);
    } catch {
      // Error reporting must never terminate the watcher.
    }
  };

  const run = async (): Promise<void> => {
    if (closed) return;

    if (running) {
      queued = true;
      return;
    }

    running = true;

    try {
      await onChange();
    } catch (error) {
      reportError(error);
    } finally {
      running = false;

      if (queued && !closed) {
        queued = false;
        await run();
      }
    }
  };

  const schedule = (relativePath: string): void => {
    if (closed) return;
    const normalized = normalizeRelativePath(relativePath);
    if (ignored.some((pattern) => pattern.test(normalized))) return;

    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      void run();
    }, debounceMs);
  };

  const closeWatcher = process.platform === 'win32'
    ? watchDirectoryTree(absoluteRoot, schedule, ignored, reportError)
    : watchRecursively(absoluteRoot, schedule, reportError);

  return () => {
    closed = true;
    queued = false;
    if (timer) clearTimeout(timer);
    closeWatcher();
  };
}

function watchRecursively(
  root: string,
  onChange: (relativePath: string) => void,
  onError: (error: unknown) => void
): () => void {
  const watcher = watch(root, { recursive: true }, (_event, filename) => {
    if (!filename) return;
    onChange(filename.toString());
  });

  watcher.on('error', onError);
  return () => watcher.close();
}

function watchDirectoryTree(
  root: string,
  onChange: (relativePath: string) => void,
  ignored: readonly RegExp[],
  onError: (error: unknown) => void
): () => void {
  const watchers = new Map<string, FSWatcher>();
  let closed = false;

  const addDirectory = (directory: string): void => {
    if (closed) return;

    const canonicalDirectory = canonicalWatchPath(directory);
    const key = canonicalDirectoryKey(canonicalDirectory);
    if (watchers.has(key)) return;

    const relativeDirectory = normalizeRelativePath(
      path.relative(root, canonicalDirectory)
    );
    if (
      relativeDirectory &&
      ignored.some((pattern) => pattern.test(relativeDirectory))
    ) {
      return;
    }

    let watcher: FSWatcher;
    try {
      watcher = watch(
        canonicalDirectory,
        { recursive: false },
        (event, filename) => {
          if (closed || !filename) return;

          const absolutePath = path.join(canonicalDirectory, filename.toString());
          const relativePath = path.relative(root, absolutePath);
          onChange(relativePath);

          if (event === 'rename') {
            tryAddNewDirectory(absolutePath);
          }
        }
      );
    } catch (error) {
      onError(error);
      return;
    }

    watchers.set(key, watcher);
    watcher.on('error', (error) => {
      onError(error);
      watcher.close();
      watchers.delete(key);
    });

    try {
      for (const entry of readdirSync(canonicalDirectory, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        addDirectory(path.join(canonicalDirectory, entry.name));
      }
    } catch (error) {
      onError(error);
    }
  };

  const tryAddNewDirectory = (candidate: string): void => {
    try {
      if (statSync(candidate).isDirectory()) {
        addDirectory(candidate);
      }
    } catch {
      // Rename events also represent deletions; a missing path needs no watcher.
    }
  };

  addDirectory(root);

  return () => {
    closed = true;
    for (const watcher of watchers.values()) {
      watcher.close();
    }
    watchers.clear();
  };
}

function canonicalWatchPath(directory: string): string {
  const resolved = path.resolve(directory);

  try {
    return realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function canonicalDirectoryKey(directory: string): string {
  return process.platform === 'win32' ? directory.toLowerCase() : directory;
}

function normalizeRelativePath(value: string): string {
  return value.replaceAll('\\', '/');
}
