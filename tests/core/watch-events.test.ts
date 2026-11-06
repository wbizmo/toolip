import { EventEmitter } from 'node:events';
import type { FSWatcher } from 'node:fs';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';

type NativeCallback = (event: string, filename: Buffer | string | null) => void;

class TestWatcher extends EventEmitter implements FSWatcher {
  close(): void {
    this.emit('close');
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }
}

describe('watchProject filename-less events', () => {
  it('runs a scan when a recursive watcher has no filename', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-watch-null-'));
    const canonicalRoot = await realpath(root);
    const listeners = new Map<string, NativeCallback>();
    const readCount = { value: 0 };
    const restorePlatform = overridePlatform('linux');
    const cleanupModules = await mockWatchers(listeners, readCount);
    const { watchProject } = await import('../../src/core/watch/watch.js');
    const scanned = deferred<void>();
    let calls = 0;
    const close = watchProject(
      root,
      async () => {
        calls += 1;
        scanned.resolve();
      },
      { debounceMs: 5 }
    );

    try {
      listeners.get(canonicalRoot)?.('change', null);
      await withTimeout(scanned.promise);
      expect(calls).toBe(1);
    } finally {
      close();
      restorePlatform();
      cleanupModules();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reconciles directories and scans after a tree watcher has no filename', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-watch-tree-'));
    const nested = path.join(root, 'nested');
    const canonicalRoot = await realpath(root);
    const listeners = new Map<string, NativeCallback>();
    const readCount = { value: 0 };
    const restorePlatform = overridePlatform('darwin');
    const cleanupModules = await mockWatchers(listeners, readCount);
    const { watchProject } = await import('../../src/core/watch/watch.js');
    const scans: Array<() => void> = [];
    let calls = 0;
    const close = watchProject(
      root,
      async () => {
        calls += 1;
        scans.shift()?.();
      },
      { debounceMs: 5 }
    );

    try {
      await mkdir(nested);
      await writeFile(path.join(nested, 'initial.txt'), 'initial', 'utf8');
      const firstScan = deferred<void>();
      scans.push(firstScan.resolve);
      const readsBeforeReconciliation = readCount.value;
      listeners.get(canonicalRoot)?.('rename', null);
      listeners.get(canonicalRoot)?.('rename', null);
      listeners.get(canonicalRoot)?.('rename', null);
      await withTimeout(firstScan.promise);

      const canonicalNested = await realpath(nested);
      expect(listeners.has(canonicalNested)).toBe(true);
      expect(readCount.value - readsBeforeReconciliation).toBe(2);

      const secondScan = deferred<void>();
      scans.push(secondScan.resolve);
      listeners.get(canonicalNested)?.('change', 'later.txt');
      await withTimeout(secondScan.promise);
      expect(calls).toBe(2);
    } finally {
      close();
      restorePlatform();
      cleanupModules();
      await rm(root, { recursive: true, force: true });
    }
  });
});

async function mockWatchers(
  listeners: Map<string, NativeCallback>,
  readCount: { value: number }
): Promise<() => void> {
  vi.resetModules();
  vi.doMock('node:fs', async () => {
    const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
    const fakeWatch = ((
      directory: string | URL,
      _options: unknown,
      listener: NativeCallback
    ) => {
      listeners.set(String(directory), listener);
      return new TestWatcher();
    }) as typeof actual.watch;
    const fakeReaddir = ((
      directory: string | Buffer | URL,
      options: unknown
    ) => {
      readCount.value += 1;
      return actual.readdirSync(directory as never, options as never);
    }) as typeof actual.readdirSync;
    return { ...actual, watch: fakeWatch, readdirSync: fakeReaddir };
  });

  return () => {
    vi.doUnmock('node:fs');
    vi.resetModules();
  };
}

function overridePlatform(platform: NodeJS.Platform): () => void {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', {
    configurable: true,
    value: platform
  });

  return () => {
    if (descriptor) Object.defineProperty(process, 'platform', descriptor);
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((next) => {
    resolve = () => next();
  });
  return { promise, resolve };
}

async function withTimeout(promise: Promise<void>): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<void>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error('Timed out waiting for scan.')),
          5_000
        );
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
