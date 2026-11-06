import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  appendHistory,
  historyFilePath,
  readHistory
} from '../../src/core/history/store.js';

const execFileAsync = promisify(execFile);
const workerPath = path.resolve('tests/helpers/local-state-worker.ts');

async function runWorker(...args: string[]): Promise<void> {
  await execFileAsync(
    process.execPath,
    ['--import', 'tsx', workerPath, ...args],
    {
      cwd: process.cwd(),
      timeout: 60_000
    }
  );
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

  it('preserves 50 unique concurrent process appends and deduplicates retries', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-processes-')
    );
    try {
      await Promise.all(
        Array.from({ length: 50 }, (_, index) =>
          runWorker('history', root, `entry-${index}`)
        )
      );
      const first = await readHistory(root);
      expect(first.entries).toHaveLength(50);
      expect(new Set(first.entries.map((entry) => entry.id)).size).toBe(50);

      await Promise.all([
        runWorker('history', root, 'retry-entry'),
        runWorker('history', root, 'retry-entry')
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
