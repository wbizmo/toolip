import { generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  parseEvidenceTrustStore,
  readEvidenceTrustStore,
  resolveEvidenceTrust
} from '../../src/core/evidence-trust-store.js';

const publicKeyPem = generateKeyPairSync('ed25519')
  .publicKey.export({ type: 'spki', format: 'pem' })
  .toString();

function store(overrides: Record<string, unknown> = {}): unknown {
  return {
    version: 1,
    projectId: 'acme/payments',
    maxAgeDays: 90,
    keys: {
      'report-key-v1': {
        publicKeyPem,
        status: 'active'
      },
      'report-key-v0': {
        publicKeyPem,
        status: 'revoked',
        revokedAt: '2026-11-01T00:00:00.000Z'
      }
    },
    ...overrides
  };
}

describe('external signed-evidence trust store', () => {
  it('resolves the exact active project key and fails closed for a revoked rotation key', () => {
    const parsed = parseEvidenceTrustStore(store());
    expect(resolveEvidenceTrust(parsed, 'report-key-v1')).toEqual({
      publicKeyPem,
      trustedKeyId: 'report-key-v1',
      expectedProjectId: 'acme/payments',
      maxAgeMs: 90 * 24 * 60 * 60 * 1000
    });
    expect(() => resolveEvidenceTrust(parsed, 'report-key-v0')).toThrow(
      'was revoked at 2026-11-01T00:00:00.000Z'
    );
    expect(() => resolveEvidenceTrust(parsed, 'unknown-key')).toThrow(
      'is not trusted'
    );
    expect(() =>
      resolveEvidenceTrust(parsed, 'report-key-v1', Number.NaN)
    ).toThrow('resolution clock is invalid');
  });

  it('rejects weak schemas, non-Ed25519 keys, invalid validity windows and accessors', () => {
    expect(() => parseEvidenceTrustStore(store({ extra: true }))).toThrow(
      'identity or version is invalid'
    );
    expect(() =>
      parseEvidenceTrustStore({
        version: 1,
        projectId: 'acme/payments',
        maxAgeDays: 90,
        keys: {
          key: { publicKeyPem: 'private', status: 'active' }
        }
      })
    ).toThrow('bounded public-key PEM');
    expect(() =>
      parseEvidenceTrustStore({
        version: 1,
        projectId: 'acme/payments',
        maxAgeDays: 90,
        keys: {
          key: {
            publicKeyPem,
            status: 'active',
            validFrom: '2026-12-01T00:00:00.000Z',
            expiresAt: '2026-11-01T00:00:00.000Z'
          }
        }
      })
    ).toThrow('invalid validity interval');
    const accessor = Object.defineProperty(
      { version: 1, projectId: 'acme/payments', maxAgeDays: 90, keys: {} },
      'extra',
      { enumerable: true, get: () => true }
    );
    expect(() => parseEvidenceTrustStore(accessor)).toThrow(
      'identity or version is invalid'
    );
  });

  it('applies key activation and expiration windows at exact UTC boundaries', () => {
    const parsed = parseEvidenceTrustStore({
      version: 1,
      projectId: 'acme/payments',
      maxAgeDays: 0,
      keys: {
        'report-key-v2': {
          publicKeyPem,
          status: 'active',
          validFrom: '2026-11-01T00:00:00.000Z',
          expiresAt: '2026-12-01T00:00:00.000Z'
        }
      }
    });
    expect(() =>
      resolveEvidenceTrust(
        parsed,
        'report-key-v2',
        Date.parse('2026-10-31T23:59:59.999Z')
      )
    ).toThrow('is not active yet');
    expect(
      resolveEvidenceTrust(
        parsed,
        'report-key-v2',
        Date.parse('2026-11-01T00:00:00.000Z')
      ).maxAgeMs
    ).toBe(0);
    expect(() =>
      resolveEvidenceTrust(
        parsed,
        'report-key-v2',
        Date.parse('2026-12-01T00:00:00.000Z')
      )
    ).toThrow('has expired');
  });

  it('loads unique-key JSON from a bounded regular file and rejects symlinks', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-trust-store-'));
    const projectRoot = path.join(root, 'project');
    await mkdir(projectRoot);
    try {
      const trustPath = path.join(root, 'trust.json');
      await writeFile(trustPath, JSON.stringify(store()), 'utf8');
      await expect(
        readEvidenceTrustStore(trustPath, projectRoot)
      ).resolves.toMatchObject({
        projectId: 'acme/payments',
        maxAgeDays: 90
      });
      const insidePath = path.join(projectRoot, 'trust.json');
      await writeFile(insidePath, JSON.stringify(store()), 'utf8');
      await expect(
        readEvidenceTrustStore(insidePath, projectRoot)
      ).rejects.toThrow('outside the verified project');
      const dotDotPrefix = path.join(projectRoot, '..evil');
      await mkdir(dotDotPrefix);
      const misleadingOutsidePath = path.join(dotDotPrefix, 'trust.json');
      await writeFile(misleadingOutsidePath, JSON.stringify(store()), 'utf8');
      await expect(
        readEvidenceTrustStore(misleadingOutsidePath, projectRoot)
      ).rejects.toThrow('outside the verified project');
      await writeFile(
        trustPath,
        '{"version":1,"version":1,"projectId":"acme/payments","maxAgeDays":90,"keys":{}}',
        'utf8'
      );
      await expect(
        readEvidenceTrustStore(trustPath, projectRoot)
      ).rejects.toThrow('duplicate keys');
      const oversizedPath = path.join(root, 'oversized.json');
      await writeFile(oversizedPath, Buffer.alloc(1024 * 1024 + 1, 0x20));
      await expect(
        readEvidenceTrustStore(oversizedPath, projectRoot)
      ).rejects.toThrow('bounded regular non-symlink');
      if (process.platform !== 'win32') {
        const linkPath = path.join(root, 'trust-link.json');
        const { symlink } = await import('node:fs/promises');
        await symlink(trustPath, linkPath);
        await expect(
          readEvidenceTrustStore(linkPath, projectRoot)
        ).rejects.toThrow('non-symlink');
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
