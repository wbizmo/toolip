import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { withLocalStateLock } from '../../src/core/local-lock.js';

describe('cross-process local-state lock ownership', () => {
  it('keeps retrying until the configured acquisition timeout', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-lock-wait-'));
    const resource = path.join(root, 'state');
    let releaseHolder: (() => void) | undefined;
    let holderStarted: (() => void) | undefined;
    const holderReady = new Promise<void>((resolve) => {
      holderStarted = resolve;
    });
    const hold = new Promise<void>((resolve) => {
      releaseHolder = resolve;
    });
    try {
      const holder = withLocalStateLock(resource, async () => {
        holderStarted?.();
        await hold;
      });
      await holderReady;
      const contender = withLocalStateLock(
        resource,
        async () => 'acquired',
        800
      );
      await new Promise((resolve) => setTimeout(resolve, 450));
      releaseHolder?.();
      await holder;
      await expect(contender).resolves.toBe('acquired');
    } finally {
      releaseHolder?.();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not release a replacement lock after its ownership token changes', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-lock-replaced-'));
    const resource = path.join(root, 'state');
    const lockPath = `${resource}.lock`;
    const ownerPath = path.join(lockPath, '.owner.replacement');
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
      expect(await readFile(ownerPath, 'utf8')).toBe('replacement-owner\n');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('removes the owner marker with the lock directory on normal release', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-lock-cleanup-'));
    const resource = path.join(root, 'state');
    const lockPath = `${resource}.lock`;
    try {
      await withLocalStateLock(resource, async () => {
        const marker = (await readdir(lockPath)).find((name) =>
          name.startsWith('.owner.')
        );
        expect(marker).toMatch(/^\.owner\.[0-9a-f-]{36}$/);
        expect((await lstat(path.join(lockPath, marker ?? ''))).isFile()).toBe(
          true
        );
      });
      await expect(lstat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
