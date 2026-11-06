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

/** Watches project files and queues serialized scans when relevant paths change. */
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

  /** Reports watcher errors without allowing callbacks to break the monitor. */
  const reportError = (error: unknown): void => {
    try {
      options.onError?.(error);
    } catch {
      // Error reporting must never terminate the watcher.
    }
  };

  /** Runs scans serially and queues a follow-up when changes arrive mid-scan. */
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

  /** Debounces changes and ignores paths excluded from security scans. */
  const schedule = (relativePath: string): void => {
    if (closed) return;
    const normalized = normalizeRelativePath(relativePath);
    if (ignored.some((pattern) => pattern.test(normalized))) return;

    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      void run();
    }, debounceMs);
  };

  const closeWatcher =
    process.platform === 'linux'
      ? watchRecursively(absoluteRoot, schedule, reportError)
      : watchDirectoryTree(absoluteRoot, schedule, ignored, reportError);

  return () => {
    closed = true;
    queued = false;
    if (timer) clearTimeout(timer);
    closeWatcher();
  };
}

/** Installs one native recursive watcher for platforms that support it reliably. */
function watchRecursively(
  root: string,
  onChange: (relativePath: string) => void,
  onError: (error: unknown) => void
): () => void {
  const watcher = watch(root, { recursive: true }, (_event, filename) => {
    onChange(filename?.toString() ?? '');
  });

  watcher.on('error', onError);
  return () => watcher.close();
}

/** Maintains per-directory watches and reconciles replaced or missed subtrees. */
function watchDirectoryTree(
  root: string,
  onChange: (relativePath: string) => void,
  ignored: readonly RegExp[],
  onError: (error: unknown) => void
): () => void {
  const watchers = new Map<
    string,
    { watcher: FSWatcher; dev: bigint; ino: bigint }
  >();
  const pendingReconciliations = new Set<string>();
  let reconciliationQueued = false;
  let closed = false;

  /** Registers a directory watcher and recursively discovers its children. */
  const addDirectory = (directory: string): void => {
    if (closed) return;

    const canonicalDirectory = canonicalWatchPath(directory);
    const key = canonicalDirectoryKey(canonicalDirectory);
    let identity: { dev: bigint; ino: bigint };
    try {
      const stat = statSync(canonicalDirectory, { bigint: true });
      if (!stat.isDirectory()) return;
      identity = { dev: stat.dev, ino: stat.ino };
    } catch {
      removeWatchTree(key);
      return;
    }

    const existing = watchers.get(key);
    if (existing?.dev === identity.dev && existing.ino === identity.ino) return;
    existing?.watcher.close();
    watchers.delete(key);

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
          if (closed || watchers.get(key)?.watcher !== watcher) return;
          if (!filename) {
            queueReconciliation(canonicalDirectory);
            onChange('');
            return;
          }

          const absolutePath = path.join(
            canonicalDirectory,
            filename.toString()
          );
          const relativePath = path.relative(root, absolutePath);
          onChange(relativePath);

          if (event === 'rename') queueReconciliation(canonicalDirectory);
        }
      );
    } catch (error) {
      onError(error);
      return;
    }

    watchers.set(key, { watcher, ...identity });
    watcher.on('error', (error) => {
      onError(error);
      watcher.close();
      if (watchers.get(key)?.watcher === watcher) watchers.delete(key);
    });

    try {
      for (const entry of readdirSync(canonicalDirectory, {
        withFileTypes: true
      })) {
        if (!entry.isDirectory()) continue;
        addDirectory(path.join(canonicalDirectory, entry.name));
      }
    } catch (error) {
      onError(error);
    }
  };

  /** Coalesces duplicate rename events for the same directory within one tick. */
  function queueReconciliation(directory: string): void {
    pendingReconciliations.add(
      canonicalDirectoryKey(canonicalWatchPath(directory))
    );
    if (reconciliationQueued) return;

    reconciliationQueued = true;
    queueMicrotask(() => {
      reconciliationQueued = false;
      const pending = [...pendingReconciliations];
      pendingReconciliations.clear();
      for (const key of pending) reconcileDirectory(key);
    });
  }

  /** Reconciles child registrations and removes watches for stale identities. */
  function reconcileDirectory(directory: string): void {
    if (closed) return;
    const directoryKey = canonicalDirectoryKey(canonicalWatchPath(directory));
    try {
      for (const entry of readdirSync(directoryKey, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          addDirectory(path.join(directoryKey, entry.name));
        }
      }
    } catch (error) {
      onError(error);
    }
    const prefix = directoryKey.endsWith(path.sep)
      ? directoryKey
      : `${directoryKey}${path.sep}`;
    for (const [key, entry] of watchers) {
      if (key !== directoryKey && !key.startsWith(prefix)) continue;
      try {
        const current = statSync(key, { bigint: true });
        if (
          !current.isDirectory() ||
          current.dev !== entry.dev ||
          current.ino !== entry.ino
        ) {
          removeWatchTree(key);
        }
      } catch {
        removeWatchTree(key);
      }
    }
  }

  /** Closes a removed directory watch and every registered descendant. */
  function removeWatchTree(directoryKey: string): void {
    const prefix = directoryKey.endsWith(path.sep)
      ? directoryKey
      : `${directoryKey}${path.sep}`;
    for (const [key, entry] of watchers) {
      if (key !== directoryKey && !key.startsWith(prefix)) continue;
      entry.watcher.close();
      watchers.delete(key);
    }
  }

  addDirectory(root);

  return () => {
    closed = true;
    pendingReconciliations.clear();
    for (const entry of watchers.values()) {
      entry.watcher.close();
    }
    watchers.clear();
  };
}

/** Resolves a watch path when possible while retaining a usable missing path. */
function canonicalWatchPath(directory: string): string {
  const resolved = path.resolve(directory);

  try {
    return realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

/** Produces a path key that follows the host platform's case rules. */
function canonicalDirectoryKey(directory: string): string {
  return process.platform === 'win32' ? directory.toLowerCase() : directory;
}

/** Normalizes native separators for ignore rules and scan notifications. */
function normalizeRelativePath(value: string): string {
  return value.replaceAll('\\', '/');
}
