import { mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
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

const algorithm = 'aes-256-gcm';

export function defaultVaultPath(): string {
  return path.join(os.homedir(), '.toolip', 'vault.json');
}

export async function initVault(masterPassword: string, vaultPath = defaultVaultPath()): Promise<void> {
  await writeEncryptedVault({ secrets: [] }, masterPassword, vaultPath);
}

export async function setSecret(input: {
  key: string;
  value: string;
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<void> {
  const vaultPath = input.vaultPath ?? defaultVaultPath();

  let data: VaultData;

  try {
    data = await readEncryptedVault(input.masterPassword, vaultPath);
  } catch {
    data = { secrets: [] };
  }

  const env = input.env ?? 'development';
  const existing = data.secrets.find((secret) => secret.key === input.key && secret.env === env);

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
}

export async function getSecret(input: {
  key: string;
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<VaultRecord> {
  const data = await readEncryptedVault(input.masterPassword, input.vaultPath ?? defaultVaultPath());
  const env = input.env ?? 'development';
  const secret = data.secrets.find((item) => item.key === input.key && item.env === env);

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
  const data = await readEncryptedVault(input.masterPassword, input.vaultPath ?? defaultVaultPath());
  const env = input.env;

  return data.secrets
    .filter((secret) => !env || secret.env === env)
    .sort((a, b) => a.key.localeCompare(b.key));
}

export async function deleteSecret(input: {
  key: string;
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<boolean> {
  const vaultPath = input.vaultPath ?? defaultVaultPath();
  const data = await readEncryptedVault(input.masterPassword, vaultPath);
  const env = input.env ?? 'development';
  const before = data.secrets.length;

  data.secrets = data.secrets.filter((secret) => !(secret.key === input.key && secret.env === env));

  await writeEncryptedVault(data, input.masterPassword, vaultPath);

  return data.secrets.length < before;
}

export async function exportEnv(input: {
  env?: string;
  masterPassword: string;
  vaultPath?: string;
}): Promise<string> {
  const secrets = await listSecrets(input);
  return secrets.map((secret) => `${secret.key}="${escapeEnv(secret.value)}"`).join('\n');
}

export async function destroyVault(vaultPath = defaultVaultPath()): Promise<void> {
  await rm(vaultPath, { force: true });
}

async function readEncryptedVault(masterPassword: string, vaultPath: string): Promise<VaultData> {
  let raw = '';

  try {
    raw = await readFile(vaultPath, 'utf8');
  } catch {
    throw new ToolipError('Vault not initialized. Run toolip vault init first.', {
      code: 'VAULT_NOT_INITIALIZED',
      exitCode: 1
    });
  }

  const parsed = JSON.parse(raw) as VaultFile;

  try {
    const key = deriveKey(masterPassword, Buffer.from(parsed.salt, 'base64'));
    const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(parsed.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(parsed.authTag, 'base64'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(parsed.data, 'base64')),
      decipher.final()
    ]);

    return JSON.parse(decrypted.toString('utf8')) as VaultData;
  } catch {
    throw new ToolipError('Invalid vault password or corrupted vault.', {
      code: 'VAULT_DECRYPT_FAILED',
      exitCode: 1
    });
  }
}

async function writeEncryptedVault(data: VaultData, masterPassword: string, vaultPath: string): Promise<void> {
  await mkdir(path.dirname(vaultPath), { recursive: true });

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

  await writeFile(vaultPath, `${JSON.stringify(file, null, 2)}\n`, 'utf8');
}

function deriveKey(masterPassword: string, salt: Buffer): Buffer {
  return crypto.scryptSync(masterPassword, salt, 32);
}

function escapeEnv(value: string): string {
  return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}
