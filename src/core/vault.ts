import crypto from 'node:crypto';
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { ToolipError } from '../errors/toolip-error.js';

export type VaultRecord = {
  key: string;
  value: string;
  env: string;
  updatedAt: string;
};

export type VaultFile = {
  version: 1;
  salt: string;
  iv: string;
  authTag: string;
  data: string;
};

export type VaultData = {
  secrets: VaultRecord[];
};

export type VaultExportFormat = 'shell' | 'json';

const algorithm = 'aes-256-gcm';
const lockTimeoutMs = 5_000;
const invalidLockStaleMs = 30_000;

export function defaultVaultPath(): string {
  return path.join(os.homedir(), '.toolip', 'vault.json');
}

export async function initVault(
  masterPassword: string,
  vaultPath = defaultVaultPath()
): Promise<void> {
  await withVaultLock(vaultPath, async () => {
    try {
      await readFile(vaultPath, 'utf8');
      throw new ToolipError('Vault already exists. Refusing to overwrite it.', {
        code: 'VAULT_ALREADY_EXISTS',
        exitCode: 1
      });
    } catch (error) {
      if (error instanceof ToolipError) throw error;
      if (errorCode(error) !== 'ENOENT') throw error;
    }

    await writeEncryptedVault({ secrets: [] }, masterPassword, vaultPath);
  });
}

export async function setSecret(input: {
  key: string;
  value: string;
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<void> {
  validateSecretKey(input.key);
  const vaultPath = input.vaultPath ?? defaultVaultPath();

  await withVaultLock(vaultPath, async () => {
    const data = await readEncryptedVault(input.masterPassword, vaultPath);
    const env = input.env ?? 'development';
    const existing = data.secrets.find(
      (secret) => secret.key === input.key && secret.env === env
    );

    if (existing) {
      existing.value = input.value;
      existing.updatedAt = new Date().toISOString();
    } else {
      data.secrets.push({
        key: input.key,
        value: input.value,
        env,
        updatedAt: new Date().toISOString()
      });
    }

    await writeEncryptedVault(data, input.masterPassword, vaultPath);
  });
}

export async function getSecret(input: {
  key: string;
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<VaultRecord> {
  const data = await readEncryptedVault(
    input.masterPassword,
    input.vaultPath ?? defaultVaultPath()
  );
  const env = input.env ?? 'development';
  const secret = data.secrets.find(
    (item) => item.key === input.key && item.env === env
  );

  if (!secret) {
    throw new ToolipError(`Secret not found: ${input.key}`, {
      code: 'VAULT_SECRET_NOT_FOUND',
      exitCode: 1
    });
  }

  return secret;
}

export async function listSecrets(input: {
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<VaultRecord[]> {
  const data = await readEncryptedVault(
    input.masterPassword,
    input.vaultPath ?? defaultVaultPath()
  );

  return data.secrets
    .filter((secret) => !input.env || secret.env === input.env)
    .sort((a, b) => a.key.localeCompare(b.key));
}

export async function deleteSecret(input: {
  key: string;
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<boolean> {
  const vaultPath = input.vaultPath ?? defaultVaultPath();

  return withVaultLock(vaultPath, async () => {
    const data = await readEncryptedVault(input.masterPassword, vaultPath);
    const env = input.env ?? 'development';
    const before = data.secrets.length;

    data.secrets = data.secrets.filter(
      (secret) => !(secret.key === input.key && secret.env === env)
    );

    if (data.secrets.length !== before) {
      await writeEncryptedVault(data, input.masterPassword, vaultPath);
    }

    return data.secrets.length < before;
  });
}

/**
 * Backward-compatible name for POSIX shell export.
 * Values are single-quoted and safe to source without expansion.
 */
export async function exportEnv(input: {
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<string> {
  return exportVault({ ...input, format: 'shell' });
}

export async function exportVault(input: {
  env?: string;
  masterPassword: string;
  vaultPath?: string;
  format: VaultExportFormat;
}): Promise<string> {
  const secrets = await listSecrets(input);

  for (const secret of secrets) validateSecretKey(secret.key);

  if (input.format === 'json') {
    return JSON.stringify(
      Object.fromEntries(secrets.map((secret) => [secret.key, secret.value])),
      null,
      2
    );
  }

  return secrets
    .map((secret) => `${secret.key}=${shellQuote(secret.value)}`)
    .join('\n');
}

export async function destroyVault(
  vaultPath = defaultVaultPath()
): Promise<void> {
  await withVaultLock(vaultPath, async () => {
    await rm(vaultPath, { force: true });
  });
}

async function readEncryptedVault(
  masterPassword: string,
  vaultPath: string
): Promise<VaultData> {
  let raw: string;

  try {
    raw = await readFile(vaultPath, 'utf8');
  } catch (error) {
    if (errorCode(error) === 'ENOENT') {
      throw new ToolipError('Vault not initialized. Run toolip vault init first.', {
        code: 'VAULT_NOT_INITIALIZED',
        exitCode: 1
      });
    }

    throw new ToolipError('Unable to read Toolip Vault.', {
      code: 'VAULT_READ_FAILED',
      exitCode: 1
    });
  }

  const parsed = parseVaultFile(raw);

  try {
    const salt = decodeBase64(parsed.salt, 16);
    const iv = decodeBase64(parsed.iv, 12);
    const authTag = decodeBase64(parsed.authTag, 16);
    const encrypted = decodeBase64(parsed.data);
    const key = deriveKey(masterPassword, salt);
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    return parseVaultData(decrypted.toString('utf8'));
  } catch (error) {
    if (error instanceof ToolipError) throw error;

    throw new ToolipError('Invalid vault password or corrupted vault.', {
      code: 'VAULT_DECRYPT_FAILED',
      exitCode: 1
    });
  }
}

async function writeEncryptedVault(
  data: VaultData,
  masterPassword: string,
  vaultPath: string
): Promise<void> {
  const directory = path.dirname(vaultPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });

  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(masterPassword, salt);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final()
  ]);

  const file: VaultFile = {
    version: 1,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    data: encrypted.toString('base64')
  };
  const tempPath = path.join(
    directory,
    `.${path.basename(vaultPath)}.${process.pid}.${crypto.randomUUID()}.tmp`
  );

  try {
    await writeFile(tempPath, `${JSON.stringify(file, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx'
    });
    await enforcePrivatePermissions(tempPath);
    await rename(tempPath, vaultPath);
    await enforcePrivatePermissions(vaultPath);
  } finally {
    await rm(tempPath, { force: true });
  }
}

async function withVaultLock<T>(
  vaultPath: string,
  operation: () => Promise<T>
): Promise<T> {
  const directory = path.dirname(vaultPath);
  const lockPath = `${vaultPath}.lock`;
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const startedAt = Date.now();

  while (true) {
    try {
      const handle = await open(lockPath, 'wx', 0o600);
      try {
        await handle.writeFile(`${process.pid}\n`, 'utf8');
        return await operation();
      } finally {
        await handle.close();
        await rm(lockPath, { force: true });
      }
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') throw error;

      if (await abandonedLock(lockPath)) {
        await rm(lockPath, { force: true });
        continue;
      }

      if (Date.now() - startedAt >= lockTimeoutMs) {
        throw new ToolipError('Toolip Vault is busy. Try again after the active mutation completes.', {
          code: 'VAULT_LOCK_TIMEOUT',
          exitCode: 1
        });
      }

      await delay(25);
    }
  }
}

async function abandonedLock(lockPath: string): Promise<boolean> {
  try {
    const raw = await readFile(lockPath, 'utf8');
    const pid = Number.parseInt(raw.trim(), 10);

    if (Number.isInteger(pid) && pid > 0) {
      try {
        process.kill(pid, 0);
        return false;
      } catch (error) {
        return errorCode(error) === 'ESRCH';
      }
    }

    const metadata = await stat(lockPath);
    return Date.now() - metadata.mtimeMs > invalidLockStaleMs;
  } catch (error) {
    return errorCode(error) === 'ENOENT';
  }
}

function parseVaultFile(raw: string): VaultFile {
  let value: unknown;

  try {
    value = JSON.parse(raw);
  } catch {
    throw corruptVault('Vault file is not valid JSON.');
  }

  if (!isRecord(value)) throw corruptVault('Vault file has an invalid shape.');
  if (value.version !== 1) {
    throw new ToolipError('Unsupported Toolip Vault version.', {
      code: 'VAULT_UNSUPPORTED_VERSION',
      exitCode: 1
    });
  }

  for (const field of ['salt', 'iv', 'authTag', 'data'] as const) {
    if (typeof value[field] !== 'string' || value[field].length === 0) {
      throw corruptVault(`Vault field ${field} is invalid.`);
    }
  }

  return value as VaultFile;
}

function parseVaultData(raw: string): VaultData {
  let value: unknown;

  try {
    value = JSON.parse(raw);
  } catch {
    throw corruptVault('Decrypted vault payload is not valid JSON.');
  }

  if (!isRecord(value) || !Array.isArray(value.secrets)) {
    throw corruptVault('Decrypted vault payload has an invalid shape.');
  }

  const secrets = value.secrets.map((record) => {
    if (
      !isRecord(record) ||
      typeof record.key !== 'string' ||
      typeof record.value !== 'string' ||
      typeof record.env !== 'string' ||
      typeof record.updatedAt !== 'string'
    ) {
      throw corruptVault('Vault contains an invalid secret record.');
    }

    return record as VaultRecord;
  });

  return { secrets };
}

function decodeBase64(value: string, expectedLength?: number): Buffer {
  if (
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw corruptVault('Vault contains invalid base64 data.');
  }

  const decoded = Buffer.from(value, 'base64');
  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    throw corruptVault('Vault cryptographic parameters have invalid lengths.');
  }
  if (decoded.length === 0) throw corruptVault('Vault contains empty encrypted data.');
  return decoded;
}

function deriveKey(masterPassword: string, salt: Buffer): Buffer {
  return crypto.scryptSync(masterPassword, salt, 32);
}

function validateSecretKey(key: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    throw new ToolipError(
      'Vault keys exported to the shell must be valid environment variable names.',
      {
        code: 'VAULT_INVALID_KEY',
        exitCode: 1
      }
    );
  }
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function enforcePrivatePermissions(filePath: string): Promise<void> {
  try {
    await chmod(filePath, 0o600);
  } catch (error) {
    if (process.platform !== 'win32') throw error;
  }
}

function corruptVault(message: string): ToolipError {
  return new ToolipError(message, {
    code: 'VAULT_CORRUPT',
    exitCode: 1
  });
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
