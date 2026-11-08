import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { AdvisorySnapshotCache } from '../../src/providers/intelligence/snapshot-cache.js';

const directories: string[] = [];

async function tempDirectory(): Promise<string> {
  const root = await mkdtemp(
    path.join(os.tmpdir(), 'toolip-advisory-snapshot-')
  );
  directories.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true }))
  );
});

describe('AdvisorySnapshotCache', () => {
  it('persists deterministic integrity-checked records with private file mode', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'advisories.json');
    const now = () => new Date('2026-11-06T12:00:00.000Z');
    const cache = await AdvisorySnapshotCache.open(file, { now });
    await cache.set('osv:v1:npm:example@1.0.0', {
      query: {
        package: { ecosystem: 'npm', name: 'example' },
        version: '1.0.0'
      },
      vulnerabilities: []
    });
    await cache.set('exploit-intel:v1:kev', {
      fetchedAt: now().toISOString(),
      asOf: '2026-11-06T00:00:00.000Z',
      entries: {}
    });
    await cache.flush();

    const raw = await readFile(file, 'utf8');
    const document = JSON.parse(raw) as { sha256: string; records: object };
    expect(document.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(Object.keys(document.records)).toEqual([
      'exploit-intel:v1:kev',
      'osv:v1:npm:example@1.0.0'
    ]);
    if (process.platform !== 'win32') {
      const { stat } = await import('node:fs/promises');
      expect((await stat(file)).mode & 0o777).toBe(0o600);
    }

    const reopened = await AdvisorySnapshotCache.open(file, { now });
    expect(reopened.recordCount).toBe(2);
    expect(reopened.ageMs('osv:v1:npm:example@1.0.0')).toBe(0);
    expect(await reopened.get('exploit-intel:v1:kev')).toMatchObject({
      asOf: '2026-11-06T00:00:00.000Z'
    });
  });

  it('rejects modified snapshots and symlink input without silently emptying cache', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'advisories.json');
    const original = await AdvisorySnapshotCache.open(file);
    await original.set('sentinel', { safe: true });
    await original.flush();
    const modified = JSON.parse(await readFile(file, 'utf8')) as {
      records: Record<string, { value: { safe: boolean } }>;
    };
    const sentinel = modified.records.sentinel;
    expect(sentinel).toBeDefined();
    if (!sentinel) throw new Error('fixture cache record is missing');
    sentinel.value.safe = false;
    await writeFile(file, JSON.stringify(modified));
    await expect(AdvisorySnapshotCache.open(file)).rejects.toThrow(
      'integrity check failed'
    );

    const alias = path.join(root, 'linked.json');
    await symlink(file, alias);
    await expect(AdvisorySnapshotCache.open(alias)).rejects.toThrow(
      'non-symlink file'
    );
  });

  it('merges concurrent updates instead of losing another writer record', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'advisories.json');
    const [first, second] = await Promise.all([
      AdvisorySnapshotCache.open(file),
      AdvisorySnapshotCache.open(file)
    ]);
    await Promise.all([
      first.set('source:first', { value: 1 }),
      second.set('source:second', { value: 2 })
    ]);
    await Promise.all([first.flush(), second.flush()]);

    const merged = await AdvisorySnapshotCache.open(file);
    expect(merged.recordCount).toBe(2);
    expect(await merged.get('source:first')).toEqual({ value: 1 });
    expect(await merged.get('source:second')).toEqual({ value: 2 });
  });

  it('signs snapshots with Ed25519 and requires an explicit trusted key', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'signed.json');
    const keys = generateKeyPairSync('ed25519');
    const privateKey = keys.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const publicKey = keys.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const signer = await AdvisorySnapshotCache.open(file, {
      signingPrivateKeyPem: privateKey,
      signingKeyId: 'release-key-1'
    });
    await signer.set('osv:v1:npm:example@1.0.0', { vulnerabilities: [] });
    await signer.flush();
    expect(signer.signatureStatus).toBe('verified');

    const verified = await AdvisorySnapshotCache.open(file, {
      trustedPublicKeyPem: publicKey,
      requireSignature: true
    });
    expect(verified.signatureStatus).toBe('verified');
    expect(await verified.get('osv:v1:npm:example@1.0.0')).toEqual({
      vulnerabilities: []
    });

    const otherKeys = generateKeyPairSync('ed25519');
    await expect(
      AdvisorySnapshotCache.open(file, {
        trustedPublicKeyPem: otherKeys.publicKey
          .export({ type: 'spki', format: 'pem' })
          .toString(),
        requireSignature: true
      })
    ).rejects.toThrow('signature verification failed');

    const unsigned = await AdvisorySnapshotCache.open(
      path.join(root, 'unsigned.json')
    );
    await expect(
      AdvisorySnapshotCache.open(unsigned.filePath, {
        trustedPublicKeyPem: publicKey,
        requireSignature: true
      })
    ).rejects.toThrow('signature is required');
  });

  it('does not silently remove a signature during an update without its key', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'signed.json');
    const keys = generateKeyPairSync('ed25519');
    const privateKey = keys.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const publicKey = keys.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const signer = await AdvisorySnapshotCache.open(file, {
      signingPrivateKeyPem: privateKey,
      signingKeyId: 'release-key-1'
    });
    await signer.set('sentinel', { value: 1 });
    await signer.flush();

    const verifier = await AdvisorySnapshotCache.open(file, {
      trustedPublicKeyPem: publicKey,
      requireSignature: true
    });
    await verifier.set('new', { value: 2 });
    await expect(verifier.flush()).rejects.toThrow('requires its signing key');
    const stillSigned = await AdvisorySnapshotCache.open(file, {
      trustedPublicKeyPem: publicKey,
      requireSignature: true
    });
    expect(stillSigned.recordCount).toBe(1);
  });

  it('does not re-sign and carry records from an untrusted snapshot', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'snapshot.json');
    const unsigned = await AdvisorySnapshotCache.open(file);
    await unsigned.set('untrusted:cached', { vulnerable: false });
    await unsigned.flush();

    const keys = generateKeyPairSync('ed25519');
    const privateKey = keys.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const publicKey = keys.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const refresh = await AdvisorySnapshotCache.open(file, {
      signingPrivateKeyPem: privateKey,
      signingKeyId: 'trusted-refresh'
    });
    await refresh.set('fresh:queried', { vulnerable: true });
    await refresh.flush();

    const signed = await AdvisorySnapshotCache.open(file, {
      trustedPublicKeyPem: publicKey,
      requireSignature: true
    });
    expect(signed.recordCount).toBe(1);
    expect(await signed.get('untrusted:cached')).toBeUndefined();
    expect(await signed.get('fresh:queried')).toEqual({ vulnerable: true });
  });
});
