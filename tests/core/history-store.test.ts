import {
  mkdtemp,
  rm
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  appendHistory,
  readHistory
} from '../../src/core/history/store.js';

describe('history store', () => {
  it('appends and reads versioned history entries', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-history-')
    );

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
});
