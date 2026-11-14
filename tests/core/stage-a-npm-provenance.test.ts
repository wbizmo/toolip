import { describe, expect, it, vi } from 'vitest';
import { verifyStageANpmProvenance } from '../../src/core/stage-a-npm-provenance.js';
import {
  parseNpmProvenancePolicy,
  type NpmProvenanceVerification
} from '../../src/providers/npm/provenance.js';
import type { DependencyIdentity } from '../../src/core/dependencies/inventory.js';

const publicScopePolicy = parseNpmProvenancePolicy({
  version: 1,
  packages: {
    widget: {
      certificateIssuer: 'https://token.actions.githubusercontent.com',
      certificateIdentity:
        'https://github.com/acme/widget/.github/workflows/release.yml@refs/heads/main',
      sourceRepository: 'https://github.com/acme/widget'
    },
    '@public/shared': {
      certificateIssuer: 'https://token.actions.githubusercontent.com',
      certificateIdentity:
        'https://github.com/acme/shared/.github/workflows/release.yml@refs/heads/main',
      sourceRepository: 'https://github.com/acme/shared'
    }
  }
});

function identity(
  name: string,
  installPath: string,
  version = '1.2.3'
): DependencyIdentity {
  return {
    id: `npm:${installPath}:${name}@${version}`,
    ecosystem: 'npm',
    name,
    version,
    direct: true,
    development: false,
    source: 'package-lock',
    resolutionConfidence: 'lockfile',
    installPath,
    integrity: `sha512-${Buffer.alloc(64, 0x42).toString('base64')}`,
    resolved: `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-${version}.tgz`,
    registry: 'https://registry.npmjs.org'
  };
}

function verifiedResult(input: DependencyIdentity): NpmProvenanceVerification {
  return {
    identityDigest: 'a'.repeat(64),
    name: input.name,
    version: input.version,
    status: 'verified',
    reason: 'verified',
    artifactIntegrity: 'verified'
  };
}

describe('Stage A npm provenance policy integration', () => {
  it('requires the exact Stage A archive digest for every lock identity', async () => {
    const first = identity('widget', 'node_modules/widget');
    const second = identity('@public/shared', 'node_modules/@public/shared');
    const digests = {
      [first.installPath as string]: '1'.repeat(128),
      [second.installPath as string]: '2'.repeat(128)
    };
    const verifier = vi.fn(async (item: DependencyIdentity) =>
      verifiedResult(item)
    );
    await expect(
      verifyStageANpmProvenance({
        identities: [first, second],
        verifiedArtifactSha512ByLocation: digests,
        allowedPublicScopes: ['@public'],
        policy: publicScopePolicy,
        verifier
      })
    ).resolves.toMatchObject({
      status: 'verified',
      artifactCount: 2,
      verifiedCount: 2,
      failureCount: 0,
      reasonCodes: []
    });
    expect(verifier).toHaveBeenNthCalledWith(
      1,
      first,
      digests[first.installPath as string],
      expect.objectContaining({ policy: publicScopePolicy })
    );
    expect(verifier).toHaveBeenNthCalledWith(
      2,
      second,
      digests[second.installPath as string],
      expect.objectContaining({ allowPublicScope: true })
    );
  });

  it('marks missing policy or withheld private scopes incomplete and mismatches blocked', async () => {
    const packageIdentity = identity('widget', 'node_modules/widget');
    const privateIdentity = identity(
      '@private/widget',
      'node_modules/@private/widget'
    );
    const digests = {
      [packageIdentity.installPath as string]: '1'.repeat(128),
      [privateIdentity.installPath as string]: '2'.repeat(128)
    };
    const notConfigured = vi.fn(async (item: DependencyIdentity) => ({
      ...verifiedResult(item),
      status: 'not_configured' as const,
      reason: 'no_package_policy' as const
    }));
    await expect(
      verifyStageANpmProvenance({
        identities: [packageIdentity],
        verifiedArtifactSha512ByLocation: {
          [packageIdentity.installPath as string]:
            digests[packageIdentity.installPath as string]
        },
        allowedPublicScopes: [],
        policy: publicScopePolicy,
        verifier: notConfigured
      })
    ).resolves.toMatchObject({
      status: 'incomplete',
      failureCount: 1,
      reasonCodes: ['no_package_policy']
    });

    const privateVerifier = vi.fn(async (item: DependencyIdentity) =>
      verifiedResult(item)
    );
    await expect(
      verifyStageANpmProvenance({
        identities: [privateIdentity],
        verifiedArtifactSha512ByLocation: {
          [privateIdentity.installPath as string]:
            digests[privateIdentity.installPath as string]
        },
        allowedPublicScopes: [],
        policy: publicScopePolicy,
        verifier: privateVerifier
      })
    ).resolves.toMatchObject({
      status: 'incomplete',
      reasonCodes: ['private_scope_consent_required']
    });
    expect(privateVerifier).not.toHaveBeenCalled();

    await expect(
      verifyStageANpmProvenance({
        identities: [packageIdentity],
        verifiedArtifactSha512ByLocation: {
          [packageIdentity.installPath as string]:
            digests[packageIdentity.installPath as string]
        },
        allowedPublicScopes: [],
        policy: publicScopePolicy,
        verifier: async (item) => ({
          ...verifiedResult(item),
          status: 'untrusted',
          reason: 'artifact_integrity_mismatch'
        })
      })
    ).resolves.toMatchObject({
      status: 'blocked',
      reasonCodes: ['artifact_integrity_mismatch']
    });
  });

  it('rejects missing, duplicate, extra or malformed verified digest identities', async () => {
    const packageIdentity = identity('widget', 'node_modules/widget');
    const installPath = packageIdentity.installPath as string;
    const valid: Record<string, string> = { [installPath]: '1'.repeat(128) };
    const options = {
      identities: [packageIdentity],
      allowedPublicScopes: [],
      policy: publicScopePolicy,
      verifier: async (item: DependencyIdentity) => verifiedResult(item)
    };
    await expect(
      verifyStageANpmProvenance({
        ...options,
        verifiedArtifactSha512ByLocation: {}
      })
    ).rejects.toThrow('identity/digest set is incomplete');
    await expect(
      verifyStageANpmProvenance({
        ...options,
        identities: [packageIdentity, packageIdentity],
        verifiedArtifactSha512ByLocation: valid
      })
    ).rejects.toThrow('identity/digest set is incomplete');
    await expect(
      verifyStageANpmProvenance({
        ...options,
        verifiedArtifactSha512ByLocation: {
          ...valid,
          extra: '2'.repeat(128)
        }
      })
    ).rejects.toThrow('identity/digest set is incomplete');
    await expect(
      verifyStageANpmProvenance({
        ...options,
        verifiedArtifactSha512ByLocation: {
          [packageIdentity.installPath as string]: 'not-a-digest'
        }
      })
    ).rejects.toThrow('identity/digest set is incomplete');
  });
});
