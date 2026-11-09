import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  readHmacKeyFile,
  readPemKeyFile
} from '../../src/core/secure-key-file.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('readPemKeyFile', () => {
  it('reads a bounded regular PEM file and rejects symlink aliases', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pem-key-'));
    roots.push(root);
    const key = path.join(root, 'public.pem');
    await writeFile(key, '-----BEGIN PUBLIC KEY-----\ntest\n');
    expect(await readPemKeyFile(key)).toContain('BEGIN PUBLIC KEY');
    const alias = path.join(root, 'alias.pem');
    await symlink(key, alias);
    await expect(readPemKeyFile(alias)).rejects.toThrow('non-symlink');
  });

  it('rejects files larger than the key byte budget', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pem-key-'));
    roots.push(root);
    const key = path.join(root, 'oversized.pem');
    await writeFile(key, Buffer.alloc(16 * 1024 + 1, 0x41));
    await expect(readPemKeyFile(key)).rejects.toThrow('size limit');
  });

  it('requires owner-only permissions for private keys on POSIX', async () => {
    if (process.platform === 'win32') return;
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pem-key-'));
    roots.push(root);
    const key = path.join(root, 'private.pem');
    await writeFile(key, 'private', { mode: 0o644 });
    await chmod(key, 0o644);
    await expect(readPemKeyFile(key, { privateKey: true })).rejects.toThrow(
      'owner-only'
    );
    await chmod(key, 0o600);
    expect(await readPemKeyFile(key, { privateKey: true })).toBe('private');
  });
});

describe('readHmacKeyFile', () => {
  it('loads a private 256-bit hex key and derives a stable non-secret key ID', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-hmac-key-'));
    roots.push(root);
    const file = path.join(root, 'history.key');
    const hex = '11'.repeat(32);
    await writeFile(file, `${hex}\n`, { mode: 0o600 });
    const loaded = await readHmacKeyFile(file);
    expect(loaded.key).toEqual(Buffer.alloc(32, 0x11));
    expect(loaded.keyId).toMatch(/^local-[a-f0-9]{24}$/u);
    expect(await readHmacKeyFile(file)).toEqual(loaded);
  });

  it('rejects shared-readable, symlinked and malformed HMAC keys', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-hmac-key-'));
    roots.push(root);
    const file = path.join(root, 'history.key');
    await writeFile(file, '22'.repeat(32), { mode: 0o644 });
    if (process.platform !== 'win32') {
      await chmod(file, 0o644);
      await expect(readHmacKeyFile(file)).rejects.toThrow('private 32-byte');
      await chmod(file, 0o600);
    }
    const alias = path.join(root, 'alias.key');
    await symlink(file, alias);
    await expect(readHmacKeyFile(alias)).rejects.toThrow('non-symlink');
    await writeFile(file, 'not-a-key', { mode: 0o600 });
    await expect(readHmacKeyFile(file)).rejects.toThrow('private 32-byte hex');
  });
});
