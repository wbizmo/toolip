import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { c as createTar } from 'tar';
import { describe, expect, it, vi } from 'vitest';
import {
  createNpmTarballAttestation,
  readNpmTarballIdentity,
  verifyNpmTarballAttestation
} from '../../src/core/npm-package-attestation.js';
import type { Bundle } from 'sigstore';

const signer = {
  certificateIssuer: 'https://token.actions.githubusercontent.com',
  certificateIdentity:
    'https://github.com/acme/toolip/.github/workflows/publish.yml@refs/heads/main'
};
const release = {
  sourceRepository: 'https://github.com/acme/toolip',
  sourceCommit: 'a'.repeat(40),
  toolipVersion: '3.2.1',
  scannerArtifactSha256: 'b'.repeat(64),
  issuedAt: '2026-11-12T00:00:00.000Z'
};
const expectedTrust = {
  expectedSourceRepository: release.sourceRepository,
  expectedSourceCommit: release.sourceCommit,
  expectedScannerArtifactSha256: release.scannerArtifactSha256
};

async function tarball(
  options: {
    name?: string;
    version?: string;
    marker?: string;
  } = {}
): Promise<Buffer> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-npm-attestation-'));
  try {
    const packageRoot = path.join(root, 'package');
    await mkdir(packageRoot);
    await writeFile(
      path.join(packageRoot, 'package.json'),
      JSON.stringify({
        name: options.name ?? 'toolip',
        version: options.version ?? '3.2.1'
      })
    );
    await writeFile(
      path.join(packageRoot, 'README.md'),
      options.marker ?? 'Toolip'
    );
    const archive = createTar({ cwd: root, gzip: true, portable: true }, [
      'package'
    ]);
    const chunks: Buffer[] = [];
    for await (const chunk of archive) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function signed(tarballBytes: Buffer): Promise<Bundle> {
  const result = await createNpmTarballAttestation(tarballBytes, {
    ...release,
    attest: async (payload, type) => {
      expect(type).toBe('application/vnd.in-toto+json');
      return {
        dsseEnvelope: {
          payload: payload.toString('base64'),
          payloadType: 'application/vnd.in-toto+json',
          signatures: [{ sig: 'test-signature' }]
        }
      } as unknown as Bundle;
    }
  });
  return result.bundle;
}

describe('exact npm package tarball attestations', () => {
  it('parses package identity without extracting or executing archive contents', async () => {
    const bytes = await tarball();
    await expect(readNpmTarballIdentity(bytes)).resolves.toEqual({
      name: 'toolip',
      version: '3.2.1'
    });
  });

  it('signs the exact tarball SHA-512, package purl, source and scanner digest', async () => {
    const bytes = await tarball();
    const attest = vi.fn(
      async (payload: Buffer) =>
        ({
          dsseEnvelope: {
            payload: payload.toString('base64'),
            payloadType: 'application/vnd.in-toto+json',
            signatures: [{ sig: 'test-signature' }]
          }
        }) as unknown as Bundle
    );
    const result = await createNpmTarballAttestation(bytes, {
      ...release,
      attest
    });
    const statement = JSON.parse(
      Buffer.from(result.bundle.dsseEnvelope.payload, 'base64').toString('utf8')
    ) as Record<string, unknown>;

    expect(result.sha512).toBe(
      createHash('sha512').update(bytes).digest('hex')
    );
    expect(result.identity).toEqual({ name: 'toolip', version: '3.2.1' });
    expect(statement.subject).toEqual([
      {
        name: 'pkg:npm/toolip@3.2.1',
        digest: { sha512: result.sha512 }
      }
    ]);
    expect(statement.predicate).toMatchObject({
      sourceRepository: release.sourceRepository,
      sourceCommit: release.sourceCommit,
      scannerArtifactSha256: release.scannerArtifactSha256
    });
    expect(attest).toHaveBeenCalledTimes(1);
    await expect(
      createNpmTarballAttestation(await tarball({ version: '9.9.9' }), {
        ...release,
        attest: vi.fn()
      })
    ).rejects.toThrow('identity must match the current Toolip package version');
  });

  it('verifies signed bundle identity and the exact archive bytes', async () => {
    const bytes = await tarball();
    const bundle = await signed(bytes);
    const verifyBundle = vi.fn(async () => true);
    await expect(
      verifyNpmTarballAttestation(bytes, bundle, {
        ...signer,
        ...expectedTrust,
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'verified',
      reason: 'verified',
      packageName: 'toolip',
      packageVersion: '3.2.1',
      sourceRepository: release.sourceRepository,
      sourceCommit: release.sourceCommit,
      scannerArtifactSha256: release.scannerArtifactSha256,
      tarballSha512: createHash('sha512').update(bytes).digest('hex')
    });
    expect(verifyBundle).toHaveBeenCalledWith(
      expect.any(Object),
      signer,
      undefined
    );
  });

  it('rejects changed bytes, source commit, repository and scanner identity before accepting a signature', async () => {
    const bytes = await tarball();
    const bundle = await signed(bytes);
    const verifyBundle = vi.fn(async () => true);
    const changedBytes = await tarball({ marker: 'changed package content' });
    await expect(
      verifyNpmTarballAttestation(changedBytes, bundle, {
        ...signer,
        ...expectedTrust,
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'subject_mismatch'
    });
    await expect(
      verifyNpmTarballAttestation(bytes, bundle, {
        ...signer,
        ...expectedTrust,
        expectedSourceCommit: 'c'.repeat(40),
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'source_commit_mismatch'
    });
    await expect(
      verifyNpmTarballAttestation(bytes, bundle, {
        ...signer,
        ...expectedTrust,
        expectedSourceRepository: 'https://github.com/attacker/toolip',
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'source_repository_mismatch'
    });
    await expect(
      verifyNpmTarballAttestation(bytes, bundle, {
        ...signer,
        ...expectedTrust,
        expectedScannerArtifactSha256: 'c'.repeat(64),
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'scanner_artifact_mismatch'
    });
    expect(verifyBundle).not.toHaveBeenCalled();
  });

  it('rejects a bad certificate verification, malformed bundles and oversized tarballs', async () => {
    const bytes = await tarball();
    const bundle = await signed(bytes);
    await expect(
      verifyNpmTarballAttestation(bytes, bundle, {
        ...signer,
        ...expectedTrust,
        verifyBundle: async () => false
      })
    ).resolves.toMatchObject({ status: 'invalid', reason: 'signature' });
    await expect(
      verifyNpmTarballAttestation(
        bytes,
        {},
        {
          ...signer,
          ...expectedTrust
        }
      )
    ).resolves.toMatchObject({ status: 'invalid', reason: 'malformed' });
    await expect(
      createNpmTarballAttestation(Buffer.alloc(32 * 1024 * 1024 + 1), release)
    ).rejects.toThrow('exceeds 32 MiB');
  });

  it('rejects non-in-toto payload types and noncanonical issue times', async () => {
    const bytes = await tarball();
    const bundle = await signed(bytes);
    const wrongPayloadType = {
      ...bundle,
      dsseEnvelope: {
        ...bundle.dsseEnvelope,
        payloadType: 'application/json'
      }
    };
    await expect(
      verifyNpmTarballAttestation(bytes, wrongPayloadType, {
        ...signer,
        ...expectedTrust,
        verifyBundle: vi.fn(async () => true)
      })
    ).resolves.toMatchObject({ status: 'invalid', reason: 'malformed' });
    await expect(
      createNpmTarballAttestation(bytes, {
        ...release,
        issuedAt: '2026-11-12',
        attest: vi.fn()
      })
    ).rejects.toThrow('issue time is invalid');
  });
});
