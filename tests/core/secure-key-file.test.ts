import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readPemKeyFile } from '../../src/core/secure-key-file.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
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
