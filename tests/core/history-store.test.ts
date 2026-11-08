import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { HistoryEntry } from '../../src/core/history/types.js';
import {
  appendHistory,
  historyFilePath,
  readHistory
} from '../../src/core/history/store.js';

const execFileAsync = promisify(execFile);
const workerPath = path.resolve('tests/helpers/local-state-worker.ts');

function historyEntry(id: string): HistoryEntry {
  return {
    id,
    createdAt: new Date().toISOString(),
    toolipVersion: '1.0.7',
    command: 'score',
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    findingIds: []
  };
}

async function runWorker(...args: string[]): Promise<void> {
  await execFileAsync(
    process.execPath,
    ['--v8-pool-size=1', '--import', 'tsx', workerPath, ...args],
    {
      cwd: process.cwd(),
      // Fifty simultaneous Node processes otherwise create several hundred
      // background threads, exceeding common hosted-runner limits before the
      // state-lock workload begins.
      env: { ...process.env, UV_THREADPOOL_SIZE: '1' },
      timeout: 60_000
    }
  );
}

async function runWorkerPool(
  tasks: readonly (() => Promise<void>)[],
  concurrency = 2
): Promise<void> {
  let next = 0;
  const failures: unknown[] = [];
  const runNext = async (): Promise<void> => {
    while (next < tasks.length) {
      const task = tasks[next++];
      if (!task) continue;
      try {
        await task();
      } catch (error) {
        failures.push(error);
      }
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(concurrency, tasks.length) }, runNext)
  );
  if (failures.length > 0)
    throw new AggregateError(failures, 'Local-state worker pool failed.');
}

describe('history store', () => {
  it('appends and reads versioned history entries', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-history-'));

    try {
      await appendHistory(root, {
        id: 'entry-1',
        createdAt: new Date().toISOString(),
        toolipVersion: '1.0.7',
        command: 'score',
        score: 82,
        summary: {
          critical: 0,
          high: 1,
          medium: 2,
          low: 0,
          info: 0,
          total: 3
        },
        findingIds: ['A', 'B', 'C']
      });

      const history = await readHistory(root);

      expect(history.schemaVersion).toBe('1.0');
      expect(history.entries).toHaveLength(1);
      expect(history.entries[0]?.score).toBe(82);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('enforces bounded retention values and preserves only the latest entries', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-retention-')
    );
    try {
      await expect(
        appendHistory(root, historyEntry('invalid'), Number.NaN)
      ).rejects.toThrow('History retention must be between');
      for (const invalid of [0, 1.5, 5_001, Number.POSITIVE_INFINITY]) {
        await expect(
          appendHistory(root, historyEntry(`invalid-${invalid}`), invalid)
        ).rejects.toThrow('History retention must be between');
      }

      for (const id of ['one', 'two', 'three'])
        await appendHistory(root, historyEntry(id), 2);

      expect(
        (await readHistory(root)).entries.map((entry) => entry.id)
      ).toEqual(['two', 'three']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('preserves 50 unique cross-process appends under contention and deduplicates retries', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-processes-')
    );
    try {
      await runWorkerPool(
        Array.from(
          { length: 50 },
          (_, index) => () => runWorker('history', root, `entry-${index}`)
        )
      );
      const first = await readHistory(root);
      expect(first.entries).toHaveLength(50);
      expect(new Set(first.entries.map((entry) => entry.id)).size).toBe(50);

      await runWorkerPool([
        () => runWorker('history', root, 'retry-entry'),
        () => runWorker('history', root, 'retry-entry')
      ]);
      const retried = await readHistory(root);
      expect(
        retried.entries.filter((entry) => entry.id === 'retry-entry')
      ).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 90_000);

  it('serializes clear with append and ignores an orphaned partial temp file', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-clear-race-')
    );
    try {
      await runWorker('history', root, 'prior');
      const filePath = historyFilePath(root);
      await writeFile(`${filePath}.orphan.tmp`, '{partial', 'utf8');
      await Promise.all([
        runWorker('history-clear', root),
        runWorker('history', root, 'racing')
      ]);
      const history = await readHistory(root);
      expect(history.entries.map((entry) => entry.id)).toEqual(
        history.entries.length === 0 ? [] : ['racing']
      );
      expect(JSON.parse(await readFile(filePath, 'utf8')).entries).toHaveLength(
        history.entries.length
      );
      expect(await readFile(`${filePath}.orphan.tmp`, 'utf8')).toBe('{partial');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
});
