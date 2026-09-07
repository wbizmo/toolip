import { watch } from 'node:fs';
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

  const watcher = watch(root, { recursive: true }, (_event, filename) => {
    if (closed || !filename) return;
    const normalized = filename.toString().replaceAll(path.sep, '/');
    if (ignored.some((pattern) => pattern.test(normalized))) return;

    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      void run();
    }, debounceMs);
  });

  watcher.on('error', reportError);

  return () => {
    closed = true;
    queued = false;
    if (timer) clearTimeout(timer);
    watcher.close();
  };
}
