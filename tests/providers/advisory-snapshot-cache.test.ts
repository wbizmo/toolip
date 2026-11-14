import {
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile
} from 'node:fs/promises';
import { execFile } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { afterEach, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { AdvisorySnapshotCache } from '../../src/providers/intelligence/snapshot-cache.js';

const directories: string[] = [];
const execFileAsync = promisify(execFile);
const snapshotWorkerPath = path.resolve(
  'tests/helpers/advisory-snapshot-worker.ts'
);

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
    let current = new Date('2026-11-06T12:00:00.000Z');
    const now = () => current;
    const cache = await AdvisorySnapshotCache.open(file, { now });
    await cache.set('osv:v1:npm:example@1.0.0', {
      query: {
        package: { ecosystem: 'npm', name: 'example' },
        version: '1.0.0'
      },
      vulnerabilities: [
        { id: 'OSV-test', modified: '2026-11-04T00:00:00.000Z' }
      ]
    });
    await cache.set('exploit-intel:v1:epss:CVE-2026-12345', {
      probability: 0.2,
      percentile: 0.8,
      asOf: '2026-11-05',
      fetchedAt: now().toISOString()
    });
    await cache.set('exploit-intel:v1:kev', {
      catalogVersion: '1.0',
      fetchedAt: now().toISOString(),
      asOf: '2026-11-06T00:00:00.000Z',
      entries: {}
    });
    await cache.flush();

    const raw = await readFile(file, 'utf8');
    const document = JSON.parse(raw) as {
      sha256: string;
      records: object;
      [key: string]: unknown;
    };
    expect(document.sha256).toMatch(/^[a-f0-9]{64}$/u);
    const schema = JSON.parse(
      await readFile(
        new URL(
          '../../docs/schemas/toolip-advisory-bundle-v1.schema.json',
          import.meta.url
        ),
        'utf8'
      )
    ) as Record<string, unknown>;
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    addFormats(ajv);
    expect(ajv.validate(schema, document)).toBe(true);
    const invalidManifest = structuredClone(document);
    (invalidManifest.manifest as { format: string }).format =
      'untrusted-source';
    expect(ajv.validate(schema, invalidManifest)).toBe(false);
    const invalidHash = structuredClone(document);
    invalidHash.sha256 = 'not-a-sha256';
    expect(ajv.validate(schema, invalidHash)).toBe(false);

    expect(Object.keys(document.records)).toEqual([
      'exploit-intel:v1:epss:CVE-2026-12345',
      'exploit-intel:v1:kev',
      'osv:v1:npm:example@1.0.0'
    ]);
    if (process.platform !== 'win32') {
      const { stat } = await import('node:fs/promises');
      expect((await stat(file)).mode & 0o777).toBe(0o600);
    }

    const reopened = await AdvisorySnapshotCache.open(file, { now });
    expect(reopened.recordCount).toBe(3);
    expect(reopened.manifest).toMatchObject({
      format: 'toolip-advisory-bundle',
      version: 1,
      recordCount: 3,
      ecosystems: ['npm'],
      sources: [
        {
          id: 'epss',
          version: 'v1',
          recordCount: 1,
          sourceUpdatedAt: '2026-11-05T00:00:00.000Z'
        },
        { id: 'kev', version: '1.0', recordCount: 1 },
        {
          id: 'osv',
          version: 'v1',
          recordCount: 1,
          sourceUpdatedAt: '2026-11-04T00:00:00.000Z'
        }
      ]
    });
    expect(reopened.ageMs('osv:v1:npm:example@1.0.0')).toBe(0);
    expect(reopened.oldestSourceAgeMs).toBe(0);
    current = new Date(current.getTime() + 31 * 24 * 60 * 60 * 1000);
    expect(reopened.oldestSourceAgeMs).toBe(31 * 24 * 60 * 60 * 1000);
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

  it('rejects future-dated snapshot generation metadata', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'future.json');
    const now = () => new Date('2026-11-06T12:00:00.000Z');
    const cache = await AdvisorySnapshotCache.open(file, { now });
    await cache.set('fixture:record', { value: 'safe' });
    await cache.flush();
    const document = JSON.parse(await readFile(file, 'utf8')) as {
      generatedAt: string;
    };
    document.generatedAt = '2026-11-07T12:00:00.000Z';
    await writeFile(file, JSON.stringify(document));
    await expect(AdvisorySnapshotCache.open(file, { now })).rejects.toThrow(
      'generation time is in the future'
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

  it('merges concurrent refresh processes after both snapshot stale bases', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'advisories.json');
    const startFile = path.join(root, 'start');
    const readyFiles = [
      path.join(root, 'first.ready'),
      path.join(root, 'second.ready')
    ];
    const workers = readyFiles.map((readyFile, index) =>
      execFileAsync(
        process.execPath,
        [
          '--v8-pool-size=1',
          '--import',
          'tsx',
          snapshotWorkerPath,
          file,
          `process:${index}`,
          readyFile,
          startFile
        ],
        {
          cwd: process.cwd(),
          env: { ...process.env, UV_THREADPOOL_SIZE: '1' },
          timeout: 30_000
        }
      ).then(
        () => undefined,
        (error: unknown) => error
      )
    );

    try {
      const deadline = Date.now() + 20_000;
      while (true) {
        const ready = await Promise.all(
          readyFiles.map(async (readyFile) => {
            try {
              await stat(readyFile);
              return true;
            } catch {
              return false;
            }
          })
        );
        if (ready.every(Boolean)) break;
        if (Date.now() > deadline)
          throw new Error('Timed out waiting for advisory snapshot workers.');
        await delay(10);
      }
      await writeFile(startFile, 'go', 'utf8');
      const workerResults = await Promise.all(workers);
      const workerError = workerResults.find(
        (result): result is Error => result instanceof Error
      );
      if (workerError) throw workerError;

      const merged = await AdvisorySnapshotCache.open(file);
      expect(merged.recordCount).toBe(2);
      expect(await merged.get('process:0')).toEqual({ writer: 'process:0' });
      expect(await merged.get('process:1')).toEqual({ writer: 'process:1' });
    } finally {
      await rm(startFile, { force: true });
    }
  }, 45_000);

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
      trustedKeyId: 'release-key-1',
      requireSignature: true
    });
    expect(verified.signatureStatus).toBe('verified');
    expect(await verified.get('osv:v1:npm:example@1.0.0')).toEqual({
      vulnerabilities: []
    });
    await expect(
      AdvisorySnapshotCache.open(file, {
        trustedPublicKeyPem: publicKey,
        trustedKeyId: 'different-trust-root',
        requireSignature: true
      })
    ).rejects.toThrow('signing key ID does not match');

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

  it('ignores an interrupted-write orphan and retains the last committed snapshot', async () => {
    const root = await tempDirectory();
    const file = path.join(root, 'advisories.json');
    const cache = await AdvisorySnapshotCache.open(file);
    await cache.set('committed', { value: 'old' });
    await cache.flush();
    await writeFile(`${file}.orphan.tmp`, '{partial', 'utf8');

    const reopened = await AdvisorySnapshotCache.open(file);

    expect(await reopened.get('committed')).toEqual({ value: 'old' });
    expect(reopened.recordCount).toBe(1);
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
