import { generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  parsePluginTrustStore,
  readPluginTrustStore,
  resolvePluginTrustKey
} from '../../src/core/plugin-trust-store.js';

const directories: string[] = [];

function keyPair() {
  const pair = generateKeyPairSync('ed25519');
  return {
    privateKey: pair.privateKey,
    publicKeyPem: pair.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString()
  };
}

function store(publicKeyPem: string, fields: Record<string, unknown> = {}) {
  return {
    version: 1,
    keys: {
      'plugin-2026': {
        publicKeyPem,
        status: 'active',
        ...fields
      }
    }
  };
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true }))
  );
});

describe('plugin signing trust stores', () => {
  it('resolves active keys at inclusive validity boundaries and rejects unknown keys', () => {
    const { publicKeyPem } = keyPair();
    const parsed = parsePluginTrustStore(
      store(publicKeyPem, {
        validFrom: '2026-11-01T00:00:00.000Z',
        expiresAt: '2026-12-01T00:00:00.000Z'
      })
    );
    expect(
      resolvePluginTrustKey(
        parsed,
        'plugin-2026',
        Date.parse('2026-11-01T00:00:00.000Z')
      ).trustedKeyId
    ).toBe('plugin-2026');
    expect(() =>
      resolvePluginTrustKey(
        parsed,
        'unknown',
        Date.parse('2026-11-15T00:00:00.000Z')
      )
    ).toThrow('not trusted');
    expect(() =>
      resolvePluginTrustKey(
        parsed,
        'plugin-2026',
        Date.parse('2026-12-01T00:00:00.000Z')
      )
    ).toThrow('has expired');
  });

  it('rejects malformed schemas, non-Ed25519 keys and expired validity windows', () => {
    const { publicKeyPem } = keyPair();
    expect(() =>
      parsePluginTrustStore({ ...store(publicKeyPem), unknown: true })
    ).toThrow('version 1');
    expect(() => parsePluginTrustStore(store('private'))).toThrow(
      'bounded public PEM'
    );
    expect(() =>
      parsePluginTrustStore(
        store(publicKeyPem, {
          validFrom: '2026-12-01T00:00:00.000Z',
          expiresAt: '2026-11-01T00:00:00.000Z'
        })
      )
    ).toThrow('invalid validity interval');
    expect(() =>
      parsePluginTrustStore(
        store(publicKeyPem, {
          status: 'revoked',
          revokedAt: '2026-11-01T00:00:00.000Z'
        })
      )
    ).not.toThrow();
  });

  it('loads only bounded external regular stores and rejects duplicate JSON keys', async () => {
    const project = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-plugin-project-')
    );
    const external = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-plugin-store-')
    );
    directories.push(project, external);
    const { publicKeyPem } = keyPair();
    const storePath = path.join(external, 'trust.json');
    await writeFile(storePath, JSON.stringify(store(publicKeyPem)));
    await expect(
      readPluginTrustStore(storePath, project)
    ).resolves.toMatchObject({
      version: 1
    });
    const inside = path.join(project, 'inside.json');
    await writeFile(inside, JSON.stringify(store(publicKeyPem)));
    await expect(readPluginTrustStore(inside, project)).rejects.toThrow(
      'outside the scanned project'
    );
    const dotDotPrefix = path.join(project, '..evil');
    await mkdir(dotDotPrefix);
    const misleadingOutsidePath = path.join(dotDotPrefix, 'trust.json');
    await writeFile(misleadingOutsidePath, JSON.stringify(store(publicKeyPem)));
    await expect(
      readPluginTrustStore(misleadingOutsidePath, project)
    ).rejects.toThrow('outside the scanned project');
    const duplicate = path.join(external, 'duplicate.json');
    await writeFile(
      duplicate,
      '{"version":1,"version":1,"keys":{"key":{"publicKeyPem":"x","status":"active"}}}'
    );
    await expect(readPluginTrustStore(duplicate, project)).rejects.toThrow(
      'duplicate keys'
    );
    const oversized = path.join(external, 'oversized.json');
    await writeFile(oversized, Buffer.alloc(1024 * 1024 + 1, 0x20));
    await expect(readPluginTrustStore(oversized, project)).rejects.toThrow(
      'bounded regular non-symlink'
    );
  });

  it('rejects a symlink trust-store path', async () => {
    const project = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-plugin-project-')
    );
    const external = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-plugin-store-')
    );
    directories.push(project, external);
    const { publicKeyPem } = keyPair();
    const realStore = path.join(external, 'trust.json');
    const link = path.join(external, 'trust-link.json');
    await writeFile(realStore, JSON.stringify(store(publicKeyPem)));
    await symlink(realStore, link);
    await expect(readPluginTrustStore(link, project)).rejects.toThrow(
      'non-symlink'
    );
  });
});
