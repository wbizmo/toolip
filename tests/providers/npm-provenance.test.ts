import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PackageURL } from 'packageurl-js';
import { describe, expect, it, vi } from 'vitest';
import {
  parseNpmProvenancePolicy,
  readNpmProvenancePolicy,
  verifyNpmProvenanceFromVerifiedArtifactSha512,
  verifyNpmProvenance
} from '../../src/providers/npm/provenance.js';
import type { DependencyIdentity } from '../../src/core/dependencies/inventory.js';

const packageName = '@acme/widget';
const version = '1.2.3';
const repository = 'https://github.com/acme/widget';
const certificateIssuer = 'https://token.actions.githubusercontent.com';
const certificateIdentity =
  'https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1.2.3';
const archiveDigest = createHash('sha512')
  .update('package bytes')
  .digest('hex');
const integrity = `sha512-${Buffer.from(archiveDigest, 'hex').toString('base64')}`;

const identity: DependencyIdentity = {
  id: 'npm:node_modules/@acme/widget:@acme/widget@1.2.3',
  ecosystem: 'npm',
  name: packageName,
  version,
  direct: true,
  development: false,
  source: 'package-lock.json',
  resolutionConfidence: 'lockfile',
  installPath: 'node_modules/@acme/widget',
  integrity,
  resolved: 'https://registry.npmjs.org/@acme%2fwidget/-/widget-1.2.3.tgz',
  registry: 'https://registry.npmjs.org'
};

const policy = parseNpmProvenancePolicy({
  version: 1,
  packages: {
    [packageName]: {
      certificateIssuer,
      certificateIdentity,
      sourceRepository: repository
    }
  }
});

function statement(overrides: Record<string, unknown> = {}) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [
      {
        name: new PackageURL('npm', '@acme', 'widget', version).toString(),
        digest: { sha512: archiveDigest }
      }
    ],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: { repository }
        }
      }
    },
    ...overrides
  };
}

function attestation(value = statement()) {
  return {
    predicateType: 'https://slsa.dev/provenance/v1',
    bundle: {
      dsseEnvelope: {
        payload: Buffer.from(JSON.stringify(value)).toString('base64'),
        signatures: [{ sig: 'signed-envelope' }]
      }
    }
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  });
}

function fetchFixture(
  options: {
    manifest?: unknown;
    attestations?: unknown;
    tarballBytes?: Buffer;
    tarballResponse?: () => Response;
  } = {}
) {
  const requests: string[] = [];
  const fetchImplementation = vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    requests.push(url);
    if (url === 'https://registry.npmjs.org/%40acme%2Fwidget')
      return jsonResponse({
        name: packageName,
        versions: {
          [version]: options.manifest ?? {
            name: packageName,
            version,
            dist: {
              integrity,
              tarball:
                'https://registry.npmjs.org/@acme%2fwidget/-/widget-1.2.3.tgz',
              attestations: {
                url: 'https://registry.npmjs.org/-/npm/v1/attestations/@acme%2Fwidget@1.2.3'
              }
            }
          }
        }
      });
    if (url.includes('/-/widget-1.2.3.tgz'))
      return (
        options.tarballResponse?.() ??
        new Response(options.tarballBytes ?? 'package bytes')
      );
    return jsonResponse(
      options.attestations ?? { attestations: [attestation()] }
    );
  });
  return { fetchImplementation, requests };
}

describe('npm provenance trust policy', () => {
  it('requires exact issuer, certificate identity, repository, package, version and lock digest', async () => {
    const { fetchImplementation, requests } = fetchFixture();
    const verifyBundle = vi.fn(async () => true);
    const verified = await verifyNpmProvenance(identity, {
      policy,
      allowPublicScope: true,
      fetchImplementation: fetchImplementation as typeof fetch,
      verifyBundle
    });

    expect(verified).toMatchObject({
      name: packageName,
      version,
      status: 'verified',
      reason: 'verified',
      sourceRepository: repository,
      certificateIssuer,
      certificateIdentity,
      artifactIntegrity: 'verified'
    });
    expect(requests).toHaveLength(3);
    expect(verifyBundle).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({
        certificateIssuer,
        certificateIdentity,
        sourceRepository: repository
      }),
      expect.any(AbortSignal)
    );
  });

  it('rejects an attestation for a different package subject before signature verification', async () => {
    const wrongSubject = statement({
      subject: [
        {
          name: new PackageURL('npm', '@acme', 'other', version).toString(),
          digest: { sha512: archiveDigest }
        }
      ]
    });
    const { fetchImplementation } = fetchFixture({
      attestations: { attestations: [attestation(wrongSubject)] }
    });
    const verifyBundle = vi.fn(async () => true);
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: fetchImplementation as typeof fetch,
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'subject_mismatch'
    });
    expect(verifyBundle).not.toHaveBeenCalled();
  });

  it('rejects a valid subject from the wrong source repository', async () => {
    const wrongRepository = statement({
      predicate: {
        buildDefinition: {
          externalParameters: {
            workflow: { repository: 'https://github.com/attacker/widget' }
          }
        }
      }
    });
    const { fetchImplementation } = fetchFixture({
      attestations: { attestations: [attestation(wrongRepository)] }
    });
    const verifyBundle = vi.fn(async () => true);
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: fetchImplementation as typeof fetch,
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'repository_mismatch'
    });
    expect(verifyBundle).not.toHaveBeenCalled();
  });

  it('hashes exact archive bytes before accepting a matching signed subject', async () => {
    const { fetchImplementation: mismatchedFetch } = fetchFixture({
      tarballBytes: Buffer.from('different archive bytes')
    });
    const verifyBundle = vi.fn(async () => true);
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: mismatchedFetch as typeof fetch,
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'artifact_integrity_mismatch',
      artifactIntegrity: 'mismatch'
    });
    expect(verifyBundle).not.toHaveBeenCalled();
  });

  it('reuses an exact Stage A archive digest and supports version-specific trust rules', async () => {
    const exactVersionPolicy = parseNpmProvenancePolicy({
      version: 1,
      packages: { [`${packageName}@${version}`]: policy.packages[packageName] }
    });
    const { fetchImplementation, requests } = fetchFixture();
    const verifyBundle = vi.fn(async () => true);
    await expect(
      verifyNpmProvenanceFromVerifiedArtifactSha512(identity, archiveDigest, {
        policy: exactVersionPolicy,
        allowPublicScope: true,
        fetchImplementation: fetchImplementation as typeof fetch,
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'verified',
      artifactIntegrity: 'verified'
    });
    expect(requests).toHaveLength(2);
    expect(verifyBundle).toHaveBeenCalledTimes(1);

    await expect(
      verifyNpmProvenanceFromVerifiedArtifactSha512(identity, '0'.repeat(128), {
        policy: exactVersionPolicy,
        allowPublicScope: true,
        fetchImplementation: fetchImplementation as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'artifact_integrity_mismatch',
      artifactIntegrity: 'mismatch'
    });
  });

  it('bounds exact archive downloads and keeps artifact integrity unknown when unavailable', async () => {
    const { fetchImplementation } = fetchFixture({
      tarballResponse: () =>
        new Response('package bytes', {
          status: 200,
          headers: {
            'content-length': String(32 * 1024 * 1024 + 1)
          }
        })
    });
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: fetchImplementation as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'unavailable',
      reason: 'response_too_large',
      artifactIntegrity: 'declared-not-verified'
    });
  });

  it('never treats a certificate verifier failure as publisher trust', async () => {
    const { fetchImplementation } = fetchFixture();
    const verifyBundle = vi.fn(async () => false);
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: fetchImplementation as typeof fetch,
        verifyBundle
      })
    ).resolves.toMatchObject({
      status: 'invalid',
      reason: 'signature_invalid'
    });
    expect(verifyBundle).toHaveBeenCalledTimes(1);
  });

  it('keeps mismatched registry origins and scoped packages private by default', async () => {
    const { fetchImplementation, requests } = fetchFixture();
    await expect(
      verifyNpmProvenance(
        { ...identity, registry: 'https://registry.example.test' },
        {
          policy,
          allowPublicScope: true,
          fetchImplementation: fetchImplementation as typeof fetch
        }
      )
    ).resolves.toMatchObject({
      status: 'withheld',
      reason: 'registry_not_public_npm'
    });
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        fetchImplementation: fetchImplementation as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'withheld',
      reason: 'private_scope_consent_required'
    });
    expect(requests).toHaveLength(0);
  });

  it('does not query when policy or a strong lock digest is absent', async () => {
    const { fetchImplementation, requests } = fetchFixture();
    await expect(
      verifyNpmProvenance(identity, {
        fetchImplementation: fetchImplementation as typeof fetch
      })
    ).resolves.toMatchObject({ status: 'not_configured' });
    await expect(
      verifyNpmProvenance(
        { ...identity, integrity: undefined },
        {
          policy,
          allowPublicScope: true,
          fetchImplementation: fetchImplementation as typeof fetch
        }
      )
    ).resolves.toMatchObject({
      status: 'unavailable',
      reason: 'lock_integrity_missing'
    });
    expect(requests).toHaveLength(0);
  });

  it('bounds registry requests and reports cancellation separately from timeout', async () => {
    const waitForAbort = vi.fn(
      (_input: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            'abort',
            () => reject(new Error('request aborted')),
            { once: true }
          );
        })
    );
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: waitForAbort as typeof fetch,
        requestTimeoutMs: 10
      })
    ).resolves.toMatchObject({
      status: 'unavailable',
      reason: 'request_timeout'
    });

    const controller = new AbortController();
    const cancellation = verifyNpmProvenance(identity, {
      policy,
      allowPublicScope: true,
      fetchImplementation: waitForAbort as typeof fetch,
      signal: controller.signal,
      requestTimeoutMs: 1000
    });
    controller.abort();
    await expect(cancellation).resolves.toMatchObject({
      status: 'unavailable',
      reason: 'cancelled'
    });
  });

  it('treats registry identity changes, oversized responses and malformed attestations as unknown or invalid', async () => {
    const { fetchImplementation: mismatchedFetch } = fetchFixture({
      manifest: {
        name: '@acme/other',
        version,
        dist: { integrity }
      }
    });
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: mismatchedFetch as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'registry_identity_mismatch'
    });

    const oversizedFetch = vi.fn(
      async () => new Response('x'.repeat(8 * 1024 * 1024 + 1), { status: 200 })
    );
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: oversizedFetch as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'unavailable',
      reason: 'response_too_large'
    });

    const { fetchImplementation: malformedFetch } = fetchFixture({
      attestations: { attestations: 'not-an-array' }
    });
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: malformedFetch as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'invalid',
      reason: 'attestation_malformed'
    });

    const { fetchImplementation: noAttestationFetch } = fetchFixture({
      attestations: { attestations: [] }
    });
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: noAttestationFetch as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'unavailable',
      reason: 'no_attestation'
    });

    const { fetchImplementation: remoteAttestationFetch, requests } =
      fetchFixture({
        manifest: {
          name: packageName,
          version,
          dist: {
            integrity,
            tarball:
              'https://registry.npmjs.org/@acme%2fwidget/-/widget-1.2.3.tgz',
            attestations: { url: 'https://attacker.example/steal' }
          }
        }
      });
    await expect(
      verifyNpmProvenance(identity, {
        policy,
        allowPublicScope: true,
        fetchImplementation: remoteAttestationFetch as typeof fetch
      })
    ).resolves.toMatchObject({
      status: 'untrusted',
      reason: 'registry_identity_mismatch'
    });
    expect(requests).toHaveLength(2);
  });

  it('rejects unknown policy fields and policies stored inside the scanned repository', async () => {
    expect(() =>
      parseNpmProvenancePolicy({
        version: 1,
        packages: {},
        allowAll: true
      })
    ).toThrow('npm provenance policy must be version 1');
    expect(() =>
      parseNpmProvenancePolicy({
        version: 1,
        packages: {
          example: {
            certificateIssuer,
            certificateIdentity,
            sourceRepository: `${repository}/extra`
          }
        }
      })
    ).toThrow('canonical GitHub URL');

    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-provenance-policy-')
    );
    try {
      const policyPath = path.join(root, 'policy.json');
      await writeFile(policyPath, JSON.stringify(policy));
      await expect(readNpmProvenancePolicy(policyPath, root)).rejects.toThrow(
        'stored outside the scanned project'
      );
      const dotDotPrefix = path.join(root, '..evil');
      await mkdir(dotDotPrefix);
      const misleadingPolicyPath = path.join(dotDotPrefix, 'policy.json');
      await writeFile(misleadingPolicyPath, JSON.stringify(policy));
      await expect(
        readNpmProvenancePolicy(misleadingPolicyPath, root)
      ).rejects.toThrow('stored outside the scanned project');
      const externalRoot = await mkdtemp(
        path.join(os.tmpdir(), 'toolip-provenance-external-')
      );
      try {
        await expect(
          readNpmProvenancePolicy(policyPath, externalRoot)
        ).resolves.toMatchObject({ version: 1 });
        const duplicatePolicyPath = path.join(externalRoot, 'duplicate.json');
        await writeFile(
          duplicatePolicyPath,
          '{"version":1,"version":1,"packages":{"example":{"certificateIssuer":"https://token.actions.githubusercontent.com","certificateIdentity":"https://github.com/acme/example/release@refs/tags/v1.0.0","sourceRepository":"https://github.com/acme/example"}}}'
        );
        await expect(
          readNpmProvenancePolicy(duplicatePolicyPath, root)
        ).rejects.toThrow('duplicate keys');
        const oversizedPolicyPath = path.join(externalRoot, 'oversized.json');
        await writeFile(
          oversizedPolicyPath,
          Buffer.alloc(1024 * 1024 + 1, 0x20)
        );
        await expect(
          readNpmProvenancePolicy(oversizedPolicyPath, root)
        ).rejects.toThrow('bounded regular non-symlink');
      } finally {
        await rm(externalRoot, { recursive: true, force: true });
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
