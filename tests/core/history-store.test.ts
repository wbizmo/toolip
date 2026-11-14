import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { HistoryEntry } from '../../src/core/history/types.js';
import {
  appendHistory,
  historyFilePath,
  protectHistoryIntegrity,
  readHistory,
  rotateHistoryIntegrityKey
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

  it('rejects history input larger than the 32 MiB storage budget', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-history-size-'));
    try {
      const filePath = historyFilePath(root);
      await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
      await writeFile(filePath, Buffer.alloc(32 * 1024 * 1024 + 1, 0x20), {
        mode: 0o600
      });
      await expect(readHistory(root)).rejects.toThrow(
        /size|byte limit|budget/iu
      );
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

  it('keeps authenticated history valid under concurrent process appends', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-signed-processes-')
    );
    const integrity = {
      key: Buffer.alloc(32, 41),
      keyId: 'multiprocess-test-key'
    };
    try {
      await runWorkerPool(
        Array.from(
          { length: 12 },
          (_, index) => () =>
            runWorker('history-signed', root, `signed-entry-${index}`)
        ),
        4
      );
      const signed = await readHistory(root, integrity);
      expect(signed.entries).toHaveLength(12);
      expect(signed.integrity?.records).toHaveLength(12);
      expect(new Set(signed.entries.map((entry) => entry.id)).size).toBe(12);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

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

  it('authenticates history entries and rejects missing trust roots or tampering', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-history-hmac-'));
    const key = Buffer.alloc(32, 7);
    const integrity = { key, keyId: 'local-test-key' };
    try {
      await appendHistory(root, historyEntry('one'), 500, integrity);
      await appendHistory(root, historyEntry('two'), 500, integrity);
      expect(
        (await readHistory(root, integrity)).entries.map((entry) => entry.id)
      ).toEqual(['one', 'two']);
      await expect(
        readHistory(root, { key: Buffer.alloc(32, 8), keyId: 'local-test-key' })
      ).rejects.toThrow('integrity verification failed');
      await expect(readHistory(root)).rejects.toThrow(
        'integrity key is required'
      );

      const filePath = historyFilePath(root);
      const document = JSON.parse(await readFile(filePath, 'utf8')) as {
        entries: HistoryEntry[];
      };
      const first = document.entries[0];
      if (!first) throw new Error('history fixture is missing its first entry');
      first.score = 99;
      await writeFile(filePath, JSON.stringify(document));
      await expect(readHistory(root, integrity)).rejects.toThrow(
        'integrity verification failed'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('detects deletion, reordering and replay, and verifies retention anchors', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-hmac-chain-')
    );
    const key = Buffer.alloc(32, 9);
    const integrity = { key, keyId: 'chain-key' };
    try {
      for (const id of ['one', 'two', 'three'])
        await appendHistory(root, historyEntry(id), 2, integrity);
      const retained = await readHistory(root, integrity);
      expect(retained.entries.map((entry) => entry.id)).toEqual([
        'two',
        'three'
      ]);
      expect(retained.integrity?.anchorSequence).toBe(1);

      const filePath = historyFilePath(root);
      const original = await readFile(filePath, 'utf8');
      const deleted = JSON.parse(original) as { entries: HistoryEntry[] };
      deleted.entries.shift();
      await writeFile(filePath, JSON.stringify(deleted));
      await expect(readHistory(root, integrity)).rejects.toThrow(
        'integrity metadata is malformed'
      );

      const reordered = JSON.parse(original) as { entries: HistoryEntry[] };
      reordered.entries.reverse();
      await writeFile(filePath, JSON.stringify(reordered));
      await expect(readHistory(root, integrity)).rejects.toThrow(
        'integrity verification failed'
      );

      const replayed = JSON.parse(original) as { entries: HistoryEntry[] };
      const first = replayed.entries[0];
      if (!first) throw new Error('history fixture is missing its first entry');
      replayed.entries[1] = structuredClone(first);
      await writeFile(filePath, JSON.stringify(replayed));
      await expect(readHistory(root, integrity)).rejects.toThrow(
        'integrity verification failed'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rotates history integrity keys only after verifying the old chain', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-hmac-rotation-')
    );
    const current = { key: Buffer.alloc(32, 11), keyId: 'old-key' };
    const next = { key: Buffer.alloc(32, 12), keyId: 'new-key' };
    try {
      await appendHistory(root, historyEntry('one'), 500, current);
      await appendHistory(root, historyEntry('two'), 500, current);
      await rotateHistoryIntegrityKey(root, current, next);
      expect(
        (await readHistory(root, next)).entries.map((entry) => entry.id)
      ).toEqual(['one', 'two']);
      await expect(readHistory(root, current)).rejects.toThrow(
        'key ID does not match'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('migrates unsigned legacy history only when explicitly protected', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-hmac-migrate-')
    );
    const integrity = { key: Buffer.alloc(32, 13), keyId: 'migration-key' };
    try {
      await appendHistory(root, historyEntry('legacy-one'));
      await appendHistory(root, historyEntry('legacy-two'));
      await protectHistoryIntegrity(root, integrity);
      const protectedHistory = await readHistory(root, integrity);
      expect(protectedHistory.entries.map((entry) => entry.id)).toEqual([
        'legacy-one',
        'legacy-two'
      ]);
      expect(protectedHistory.integrity?.records).toHaveLength(2);
      await expect(protectHistoryIntegrity(root, integrity)).rejects.toThrow(
        'already has an integrity chain'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('accepts the documented 500 and 5,000 entry retention ceilings', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-retention-ceilings-')
    );
    try {
      await appendHistory(root, historyEntry('default-retention'), 500);
      await appendHistory(root, historyEntry('maximum-retention'), 5_000);
      await expect(
        appendHistory(root, historyEntry('too-many'), 5_001)
      ).rejects.toThrow('between 1 and 5000');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
