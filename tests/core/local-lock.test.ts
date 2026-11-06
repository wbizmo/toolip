import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { withLocalStateLock } from '../../src/core/local-lock.js';

describe('cross-process local-state lock ownership', () => {
  it('does not release a replacement lock after its ownership token changes', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-lock-replaced-'));
    const resource = path.join(root, 'state');
    const lockPath = `${resource}.lock`;
    const ownerPath = `${lockPath}.owner`;
    try {
      await expect(
        withLocalStateLock(resource, async (assertOwned) => {
          await rm(lockPath, { recursive: true });
          await mkdir(lockPath, { mode: 0o700 });
          await writeFile(ownerPath, 'replacement-owner\n', 'utf8');
          await expect(assertOwned()).rejects.toMatchObject({
            code: 'LOCAL_STATE_LOCK_COMPROMISED'
          });
        })
      ).rejects.toMatchObject({ code: 'LOCAL_STATE_LOCK_COMPROMISED' });

      expect((await stat(lockPath)).isDirectory()).toBe(true);
      expect(
        await import('node:fs/promises').then(({ readFile }) =>
          readFile(ownerPath, 'utf8')
        )
      ).toBe('replacement-owner\n');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
