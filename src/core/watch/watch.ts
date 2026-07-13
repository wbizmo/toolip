import { watch } from 'node:fs';
import path from 'node:path';

export type WatchOptions = {
  debounceMs?: number;
  ignored?: RegExp[];
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

  const run = async (): Promise<void> => {
    if (running) {
      queued = true;
      return;
    }

    running = true;

    try {
      await onChange();
    } finally {
      running = false;

      if (queued) {
        queued = false;
        await run();
      }
    }
  };

  const watcher = watch(root, { recursive: true }, (_event, filename) => {
    if (!filename) return;
    const normalized = filename.toString().replaceAll(path.sep, '/');
    if (ignored.some((pattern) => pattern.test(normalized))) return;

    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      void run();
    }, debounceMs);
  });

  return () => {
    if (timer) clearTimeout(timer);
    watcher.close();
  };
}
