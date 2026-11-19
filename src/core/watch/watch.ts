import {
  opendirSync,
  realpathSync,
  statSync,
  watch,
  type FSWatcher
} from 'node:fs';
import path from 'node:path';

export type WatchOptions = {
  debounceMs?: number;
  /** Maximum active directory watches on platforms without native recursion. */
  maxDirectories?: number;
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
  const maximumWatchDirectories = options.maxDirectories ?? 50_000;
  if (
    !Number.isSafeInteger(maximumWatchDirectories) ||
    maximumWatchDirectories < 1 ||
    maximumWatchDirectories > 50_000
  )
    throw new RangeError('Watch directory limit must be from 1 to 50,000.');
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
      : watchDirectoryTree(
          absoluteRoot,
          schedule,
          ignored,
          reportError,
          maximumWatchDirectories
        );

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
  onError: (error: unknown) => void,
  maximumWatchDirectories: number
): () => void {
  const watchers = new Map<
    string,
    { watcher: FSWatcher; dev: bigint; ino: bigint }
  >();
  const pendingReconciliations = new Set<string>();
  const rootKey = canonicalDirectoryKey(root);
  let rootRecoveryTimer: NodeJS.Timeout | undefined;
  let reconciliationQueued = false;
  let closed = false;
  let directoryLimitReported = false;

  /** Retries root registration while a temporarily moved root is unavailable. */
  function scheduleRootRecovery(): void {
    if (closed || rootRecoveryTimer) return;
    rootRecoveryTimer = setTimeout(() => {
      rootRecoveryTimer = undefined;
      if (closed || watchers.has(rootKey)) return;
      addDirectory(root);
      if (!watchers.has(rootKey)) scheduleRootRecovery();
    }, 100);
    rootRecoveryTimer.unref();
  }

  /** Registers directory watchers with bounded, iterative subtree discovery. */
  const addDirectory = (directory: string): void => {
    if (closed) return;
    const pendingDirectories = [directory];
    while (pendingDirectories.length > 0 && !closed) {
      const candidate = pendingDirectories.pop();
      if (!candidate) continue;
      const canonicalDirectory = canonicalWatchPath(candidate);
      const key = canonicalDirectoryKey(canonicalDirectory);
      let identity: { dev: bigint; ino: bigint };
      try {
        const stat = statSync(canonicalDirectory, { bigint: true });
        if (!stat.isDirectory()) continue;
        identity = { dev: stat.dev, ino: stat.ino };
      } catch {
        removeWatchTree(key);
        if (key === rootKey) scheduleRootRecovery();
        continue;
      }

      const existing = watchers.get(key);
      if (existing?.dev === identity.dev && existing.ino === identity.ino)
        continue;
      if (existing) removeWatchTree(key);

      const relativeDirectory = normalizeRelativePath(
        path.relative(root, canonicalDirectory)
      );
      if (
        relativeDirectory &&
        ignored.some((pattern) => pattern.test(relativeDirectory))
      )
        continue;

      if (watchers.size >= maximumWatchDirectories) {
        if (!directoryLimitReported) {
          directoryLimitReported = true;
          onError(
            new Error(
              `Project watch directory limit reached (${maximumWatchDirectories}); deeper paths are not monitored.`
            )
          );
        }
        continue;
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
        if (key === rootKey) scheduleRootRecovery();
        continue;
      }

      watchers.set(key, { watcher, ...identity });
      if (key === rootKey && rootRecoveryTimer) {
        clearTimeout(rootRecoveryTimer);
        rootRecoveryTimer = undefined;
      }
      watcher.on('error', (error) => {
        onError(error);
        watcher.close();
        if (watchers.get(key)?.watcher === watcher) {
          removeWatchTree(key);
          if (key === rootKey) scheduleRootRecovery();
        }
      });

      visitChildDirectories(
        canonicalDirectory,
        (childDirectory) => {
          if (
            watchers.size + pendingDirectories.length >=
            maximumWatchDirectories
          ) {
            if (!directoryLimitReported) {
              directoryLimitReported = true;
              onError(
                new Error(
                  `Project watch directory limit reached (${maximumWatchDirectories}); deeper paths are not monitored.`
                )
              );
            }
            return false;
          }
          pendingDirectories.push(childDirectory);
          return true;
        },
        onError
      );
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
    visitChildDirectories(
      directoryKey,
      (childDirectory) => {
        if (watchers.size >= maximumWatchDirectories) {
          if (!directoryLimitReported) {
            directoryLimitReported = true;
            onError(
              new Error(
                `Project watch directory limit reached (${maximumWatchDirectories}); deeper paths are not monitored.`
              )
            );
          }
          return false;
        }
        addDirectory(childDirectory);
        return true;
      },
      (error) => {
        onError(error);
        if (directoryKey === rootKey) scheduleRootRecovery();
      }
    );
    for (const [key, entry] of watchers) {
      if (key !== directoryKey && path.dirname(key) !== directoryKey) continue;
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
    if (rootRecoveryTimer) clearTimeout(rootRecoveryTimer);
    rootRecoveryTimer = undefined;
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

/** Iterates child directories without materializing a full directory listing. */
function visitChildDirectories(
  directory: string,
  visit: (childDirectory: string) => boolean,
  onError: (error: unknown) => void
): void {
  let handle: ReturnType<typeof opendirSync> | undefined;
  let exhausted = false;
  try {
    handle = opendirSync(directory);
    let entry = handle.readSync();
    while (entry) {
      if (entry.isDirectory() && !visit(path.join(directory, entry.name)))
        break;
      entry = handle.readSync();
    }
    exhausted = entry === null;
  } catch (error) {
    onError(error);
  } finally {
    if (!exhausted) {
      try {
        handle?.closeSync();
      } catch (error) {
        onError(error);
      }
    }
  }
}
