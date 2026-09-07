import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  access,
  chmod,
  mkdtemp,
  readdir,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ToolipError } from '../src/errors/toolip-error.js';
import {
  deleteSecret,
  exportEnv,
  exportVault,
  getSecret,
  initVault,
  listSecrets,
  setSecret
} from '../src/core/vault.js';

const execFileAsync = promisify(execFile);

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
      expect(exported).toContain(
        "DATABASE_URL='postgres://user:pass@localhost:5432/app'"
      );

      const json = await exportVault({
        masterPassword: 'master-password',
        vaultPath,
        format: 'json'
      });
      expect(JSON.parse(json)).toEqual({
        DATABASE_URL: 'postgres://user:pass@localhost:5432/app'
      });

      expect(
        await deleteSecret({
          key: 'DATABASE_URL',
          env: 'development',
          masterPassword: 'master-password',
          vaultPath
        })
      ).toBe(true);
      expect(
        await listSecrets({ masterPassword: 'master-password', vaultPath })
      ).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('quotes shell export so expansion and command substitution stay inert', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-shell-'));
    const vaultPath = path.join(root, 'vault.json');
    const marker = path.join(root, 'should-not-exist');
    const value = `$HOME $(touch ${marker}) \`touch ${marker}\` 'quoted'\nsecond line`;

    try {
      await initVault('master-password', vaultPath);
      await setSecret({
        key: 'DANGEROUS',
        value,
        masterPassword: 'master-password',
        vaultPath
      });

      const exported = await exportEnv({
        masterPassword: 'master-password',
        vaultPath
      });
      expect(exported).toContain('$HOME');
      expect(exported).toContain("'\"'\"'");

      if (process.platform !== 'win32') {
        const script = path.join(root, 'export.sh');
        await writeFile(script, `${exported}\nprintf '%s' "$DANGEROUS"\n`, 'utf8');
        const { stdout } = await execFileAsync('/bin/sh', [script]);
        expect(stdout).toBe(value);
        await expect(access(marker)).rejects.toMatchObject({ code: 'ENOENT' });
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('serializes concurrent mutations without losing updates', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-concurrent-'));
    const vaultPath = path.join(root, 'vault.json');

    try {
      await initVault('master-password', vaultPath);
      await Promise.all([
        setSecret({
          key: 'FIRST',
          value: 'one',
          masterPassword: 'master-password',
          vaultPath
        }),
        setSecret({
          key: 'SECOND',
          value: 'two',
          masterPassword: 'master-password',
          vaultPath
        })
      ]);

      const secrets = await listSecrets({
        masterPassword: 'master-password',
        vaultPath
      });
      expect(secrets.map((secret) => secret.key)).toEqual(['FIRST', 'SECOND']);
      expect(
        (await readdir(root)).some((file) => file.endsWith('.tmp'))
      ).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('limits shell-key validation to shell export and normalizes malformed vault files', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-corrupt-'));
    const vaultPath = path.join(root, 'vault.json');

    try {
      await initVault('master-password', vaultPath);
      await setSecret({
        key: 'legacy.key',
        value: 'value',
        masterPassword: 'master-password',
        vaultPath
      });

      const json = await exportVault({
        masterPassword: 'master-password',
        vaultPath,
        format: 'json'
      });
      expect(JSON.parse(json)).toEqual({ 'legacy.key': 'value' });

      await expect(
        exportVault({
          masterPassword: 'master-password',
          vaultPath,
          format: 'shell'
        })
      ).rejects.toMatchObject({ code: 'VAULT_INVALID_KEY' });

      await writeFile(vaultPath, '{not-json', 'utf8');
      await expect(
        listSecrets({ masterPassword: 'master-password', vaultPath })
      ).rejects.toMatchObject({
        name: 'ToolipError',
        code: 'VAULT_CORRUPT'
      } satisfies Partial<ToolipError>);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('creates and repairs private vault permissions where POSIX modes apply', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-mode-'));
    const vaultPath = path.join(root, 'vault.json');

    try {
      await initVault('master-password', vaultPath);
      if (process.platform !== 'win32') {
        expect((await stat(vaultPath)).mode & 0o777).toBe(0o600);
        await chmod(vaultPath, 0o644);
        await listSecrets({ masterPassword: 'master-password', vaultPath });
        expect((await stat(vaultPath)).mode & 0o777).toBe(0o600);
      }
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
