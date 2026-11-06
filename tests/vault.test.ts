import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import {
  access,
  chmod,
  chown,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  symlink,
  utimes,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { describe, expect, it } from 'vitest';
import type { ToolipError } from '../src/errors/toolip-error.js';
import { withLocalStateLock } from '../src/core/local-lock.js';
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
const workerPath = path.resolve('tests/helpers/local-state-worker.ts');

async function runWorker(...args: string[]): Promise<void> {
  await execFileAsync(
    process.execPath,
    ['--import', 'tsx', workerPath, ...args],
    {
      cwd: process.cwd(),
      timeout: 30_000
    }
  );
}

async function waitForFile(filePath: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      await access(filePath);
      return;
    } catch {
      await delay(20);
    }
  }
  throw new Error(`Worker did not create its ready marker: ${filePath}`);
}

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
  }, 30_000);

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
        await writeFile(
          script,
          `${exported}\nprintf '%s' "$DANGEROUS"\n`,
          'utf8'
        );
        const { stdout } = await execFileAsync('/bin/sh', [script]);
        expect(stdout).toBe(value);
        await expect(access(marker)).rejects.toMatchObject({ code: 'ENOENT' });
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('serializes concurrent mutations without losing updates', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-vault-concurrent-')
    );
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
      expect((await readdir(root)).some((file) => file.endsWith('.tmp'))).toBe(
        false
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 20_000);

  it('serializes mutations from three independent processes', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-vault-processes-')
    );
    const vaultPath = path.join(root, 'vault.json');
    try {
      await initVault('worker-test-password', vaultPath);
      await Promise.all(
        ['FIRST_PROCESS', 'SECOND_PROCESS', 'THIRD_PROCESS'].map((key) =>
          runWorker('vault', vaultPath, key, `value-${key}`)
        )
      );
      const secrets = await listSecrets({
        masterPassword: 'worker-test-password',
        vaultPath
      });
      expect(secrets.map((secret) => secret.key).sort()).toEqual([
        'FIRST_PROCESS',
        'SECOND_PROCESS',
        'THIRD_PROCESS'
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 45_000);

  it('keeps a live process lock in place while contenders wait', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-vault-live-lock-')
    );
    const vaultPath = path.join(root, 'vault.json');
    const readyPath = path.join(root, 'ready');
    try {
      await initVault('worker-test-password', vaultPath);
      const holder = spawn(
        process.execPath,
        [
          '--import',
          'tsx',
          workerPath,
          'hold-lock',
          vaultPath,
          'unused',
          '1200',
          readyPath
        ],
        { cwd: process.cwd(), stdio: 'ignore' }
      );
      await waitForFile(readyPath);
      const lockPath = `${vaultPath}.lock`;
      const [lockInfo, ownerFiles] = await Promise.all([
        stat(lockPath),
        readdir(root)
      ]);
      const ownerFile = ownerFiles.find((file) =>
        /^vault\.json\.lock\.owner\.[0-9a-f-]{36}$/i.test(file)
      );
      expect(ownerFile).toBeDefined();
      const owner = await readFile(path.join(root, ownerFile ?? ''), 'utf8');
      expect(lockInfo.isDirectory()).toBe(true);
      expect(owner.trim()).toMatch(/^[0-9a-f-]{36}$/i);
      if (process.platform !== 'win32') {
        expect(lockInfo.mode & 0o777).toBe(0o700);
      }
      const holderExit = new Promise<void>((resolve, reject) => {
        holder.once('error', reject);
        holder.once('exit', (code) =>
          code === 0
            ? resolve()
            : reject(new Error(`Lock holder exited ${code}.`))
        );
      });
      await runWorker('vault', vaultPath, 'CONTENDER', 'waited');
      await holderExit;
      await expect(lstat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('reclaims a stale lock left by a terminated owner process', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-vault-stale-owner-')
    );
    const resource = path.join(root, 'state');
    const readyPath = path.join(root, 'ready');
    const staleMs = 1_500;
    let holder: ReturnType<typeof spawn> | undefined;
    try {
      holder = spawn(
        process.execPath,
        [
          '--import',
          'tsx',
          workerPath,
          'hold-lock',
          resource,
          'unused',
          '10000',
          readyPath,
          String(staleMs)
        ],
        { cwd: process.cwd(), stdio: 'ignore' }
      );
      await waitForFile(readyPath);
      const markerPrefix = `${path.basename(`${resource}.lock`)}.owner.`;
      expect(
        (await readdir(root)).some((entry) => entry.startsWith(markerPrefix))
      ).toBe(true);
      const holderExit = new Promise<void>((resolve, reject) => {
        holder?.once('error', reject);
        holder?.once('exit', () => resolve());
      });
      holder.kill('SIGKILL');
      await holderExit;
      await delay(staleMs + 250);

      await expect(
        withLocalStateLock(resource, async () => 'recovered', 4_000, staleMs)
      ).resolves.toBe('recovered');
      expect(
        (await readdir(root)).some((entry) => entry.startsWith(markerPrefix))
      ).toBe(false);
    } finally {
      holder?.kill('SIGKILL');
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('recovers the stale lease left by a crashed or PID-reused owner', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-vault-crashed-lock-')
    );
    const resource = path.join(root, 'state');
    try {
      const lockPath = `${resource}.lock`;
      await mkdir(lockPath, { mode: 0o700 });
      await writeFile(`${lockPath}.owner`, `pid=${process.pid}\n`, 'utf8');
      const staleTime = new Date(Date.now() - 5_000);
      await utimes(lockPath, staleTime, staleTime);
      const { withLocalStateLock } = await import('../src/core/local-lock.js');
      await withLocalStateLock(
        resource,
        async (assertOwned) => assertOwned(),
        5_000,
        2_000
      );
      await expect(lstat(`${resource}.lock`)).rejects.toMatchObject({
        code: 'ENOENT'
      });
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
  }, 15_000);

  it('creates and repairs private vault permissions where POSIX modes apply', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-mode-'));
    const vaultPath = path.join(root, 'vault.json');

    try {
      await initVault('master-password', vaultPath);
      if (process.platform !== 'win32') {
        expect((await stat(vaultPath)).mode & 0o777).toBe(0o600);
        await chmod(vaultPath, 0o644);
        await chmod(root, 0o755);
        await listSecrets({ masterPassword: 'master-password', vaultPath });
        expect((await stat(vaultPath)).mode & 0o777).toBe(0o600);
        expect((await stat(root)).mode & 0o777).toBe(0o700);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it.skipIf(process.platform === 'win32')(
    'rejects a symlink vault and accepts a symlinked parent directory',
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), 'toolip-vault-symlink-')
      );
      const target = path.join(root, '.toolip', 'vault.json');
      const linkedVault = path.join(root, 'linked-vault.json');
      const parentAlias = path.join(root, 'parent-alias');
      const finalDirectoryAlias = path.join(root, 'final-directory-alias');
      const linkedParentVault = path.join(parentAlias, '.toolip', 'vault.json');
      try {
        await initVault('master-password', target);
        await chmod(target, 0o644);
        await symlink(target, linkedVault);
        await expect(
          listSecrets({
            masterPassword: 'master-password',
            vaultPath: linkedVault
          })
        ).rejects.toMatchObject({ code: 'VAULT_READ_FAILED' });
        expect((await stat(target)).mode & 0o777).toBe(0o644);

        await chmod(target, 0o600);
        await symlink(path.dirname(target), finalDirectoryAlias, 'dir');
        await expect(
          listSecrets({
            masterPassword: 'master-password',
            vaultPath: path.join(finalDirectoryAlias, 'vault.json')
          })
        ).rejects.toMatchObject({
          code: 'VAULT_READ_FAILED',
          message: expect.stringContaining(
            'Local state directory must be a real, non-symlink directory.'
          )
        });

        await symlink(root, parentAlias, 'dir');
        await expect(
          listSecrets({
            masterPassword: 'master-password',
            vaultPath: linkedParentVault
          })
        ).resolves.toEqual([]);
        expect((await stat(target)).mode & 0o777).toBe(0o600);

        const linkedFinalDirectoryVault = path.join(parentAlias, 'vault.json');
        await expect(
          initVault('master-password', linkedFinalDirectoryVault)
        ).rejects.toMatchObject({ code: 'UNSAFE_LOCAL_STATE_PATH' });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  it.skipIf(process.platform === 'win32' || process.geteuid?.() !== 0)(
    'rejects vault files and directories owned by another user',
    async () => {
      const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-vault-owner-'));
      const vaultPath = path.join(root, 'vault.json');
      const foreignUid = (process.geteuid?.() ?? 0) + 1;
      try {
        await initVault('master-password', vaultPath);
        await chown(vaultPath, foreignUid, process.getegid?.() ?? 0);
        await expect(
          listSecrets({ masterPassword: 'master-password', vaultPath })
        ).rejects.toMatchObject({ code: 'VAULT_READ_FAILED' });

        await chown(
          vaultPath,
          process.geteuid?.() ?? 0,
          process.getegid?.() ?? 0
        );
        await chown(root, foreignUid, process.getegid?.() ?? 0);
        await expect(
          listSecrets({ masterPassword: 'master-password', vaultPath })
        ).rejects.toMatchObject({ code: 'VAULT_READ_FAILED' });
      } finally {
        await chown(root, process.geteuid?.() ?? 0, process.getegid?.() ?? 0);
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  it('rejects invalid master passwords', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-vault-bad-pass-')
    );
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
