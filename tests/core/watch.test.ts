import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { watchProject } from '../../src/core/watch/watch.js';

describe('watchProject', () => {
  it('reports callback failures and continues watching', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-watch-'));
    let calls = 0;
    const errors: string[] = [];

    const firstFailure = deferred<void>();
    const recovered = deferred<void>();
    const close = watchProject(
      root,
      async () => {
        calls += 1;
        if (calls === 1) throw new Error('first run failed');
        recovered.resolve();
      },
      {
        debounceMs: 20,
        onError(error) {
          errors.push(error instanceof Error ? error.message : String(error));
          firstFailure.resolve();
        }
      }
    );

    try {
      await writeFile(path.join(root, 'first.txt'), 'one', 'utf8');
      await withTimeout(firstFailure.promise, 3_000);

      await writeFile(path.join(root, 'second.txt'), 'two', 'utf8');
      await withTimeout(recovered.promise, 3_000);

      expect(errors).toContain('first run failed');
      expect(calls).toBeGreaterThanOrEqual(2);
    } finally {
      close();
      await rm(root, { recursive: true, force: true });
    }
  });
});

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Timed out after ${timeoutMs}ms.`)),
          timeoutMs
        );
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
