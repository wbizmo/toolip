import { describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  deleteSecret,
  exportEnv,
  getSecret,
  initVault,
  listSecrets,
  setSecret
} from '../src/core/vault.js';

describe('Toolip Vault', () => {
  it('initializes, stores, retrieves, lists, exports, and deletes secrets', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-'));
    const vaultPath = path.join(root, 'vault.json');

    try {
      await initVault('master-password', vaultPath);

      await setSecret({
        key: 'DATABASE_URL',
        value: 'postgres://user:pass@localhost:5432/app',
        env: 'development',
        masterPassword: 'master-password',
        vaultPath
      });

      const secret = await getSecret({
        key: 'DATABASE_URL',
        env: 'development',
        masterPassword: 'master-password',
        vaultPath
      });

      expect(secret.value).toBe('postgres://user:pass@localhost:5432/app');

      const secrets = await listSecrets({
        masterPassword: 'master-password',
        vaultPath
      });

      expect(secrets).toHaveLength(1);
      expect(secrets[0]?.key).toBe('DATABASE_URL');

      const exported = await exportEnv({
        masterPassword: 'master-password',
        vaultPath
      });

      expect(exported).toContain('DATABASE_URL="postgres://user:pass@localhost:5432/app"');

      const deleted = await deleteSecret({
        key: 'DATABASE_URL',
        env: 'development',
        masterPassword: 'master-password',
        vaultPath
      });

      expect(deleted).toBe(true);

      const afterDelete = await listSecrets({
        masterPassword: 'master-password',
        vaultPath
      });

      expect(afterDelete).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects invalid master passwords', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-bad-pass-'));
    const vaultPath = path.join(root, 'vault.json');

    try {
      await initVault('correct-password', vaultPath);

      await expect(
        listSecrets({
          masterPassword: 'wrong-password',
          vaultPath
        })
      ).rejects.toThrow('Invalid vault password or corrupted vault.');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
