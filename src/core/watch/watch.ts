import {
  readdirSync,
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
  const absoluteRoot = path.resolve(root);
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

    const key = canonicalDirectoryKey(directory);
    if (watchers.has(key)) return;

    const relativeDirectory = normalizeRelativePath(path.relative(root, directory));
    if (
      relativeDirectory &&
      ignored.some((pattern) => pattern.test(relativeDirectory))
    ) {
      return;
    }

    let watcher: FSWatcher;
    try {
      watcher = watch(directory, { recursive: false }, (event, filename) => {
        if (closed || !filename) return;

        const absolutePath = path.join(directory, filename.toString());
        const relativePath = path.relative(root, absolutePath);
        onChange(relativePath);

        if (event === 'rename') {
          tryAddNewDirectory(absolutePath);
        }
      });
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
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        addDirectory(path.join(directory, entry.name));
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

function canonicalDirectoryKey(directory: string): string {
  const resolved = path.resolve(directory);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function normalizeRelativePath(value: string): string {
  return value.replaceAll('\\', '/');
}
