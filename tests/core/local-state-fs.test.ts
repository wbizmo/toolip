import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  assertDirectoryIdentity,
  ensurePrivateDirectory,
  openPrivateFile
} from '../../src/core/local-state-fs.js';

describe('private local-state filesystem access', () => {
  it.skipIf(process.platform === 'win32')(
    'rejects a FIFO without blocking for a writer',
    async () => {
      const root = mkdtempSync(path.join(os.tmpdir(), 'toolip-local-state-'));
      const fifo = path.join(root, 'state');
      try {
        execFileSync('mkfifo', [fifo]);

        await expect(openPrivateFile(fifo)).rejects.toMatchObject({
          code: 'UNSAFE_LOCAL_STATE_PATH'
        });
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
    2_000
  );

  it('rejects a parent directory swapped after validation', async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'toolip-parent-swap-'));
    const stateDirectory = path.join(root, '.toolip');
    const displacedDirectory = path.join(root, '.toolip.validated');
    try {
      const identity = await ensurePrivateDirectory(stateDirectory);
      renameSync(stateDirectory, displacedDirectory);
      mkdirSync(stateDirectory, { mode: 0o700 });

      await expect(
        assertDirectoryIdentity(stateDirectory, identity)
      ).rejects.toMatchObject({ code: 'UNSAFE_LOCAL_STATE_PATH' });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
