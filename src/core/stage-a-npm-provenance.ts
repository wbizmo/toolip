import { mapConcurrent } from '../application/concurrency.js';
import type { DependencyIdentity } from './dependencies/inventory.js';
import {
  verifyNpmProvenanceFromVerifiedArtifactSha512,
  type NpmProvenanceOptions,
  type NpmProvenancePolicy,
  type NpmProvenanceVerification
} from '../providers/npm/provenance.js';

export type StageANpmProvenanceResult = Readonly<{
  status: 'verified' | 'incomplete' | 'blocked';
  artifactCount: number;
  verifiedCount: number;
  failureCount: number;
  reasonCodes: readonly string[];
}>;

type StageANpmProvenanceOptions = Readonly<{
  identities: readonly DependencyIdentity[];
  verifiedArtifactSha512ByLocation: Readonly<Record<string, string>>;
  allowedPublicScopes: readonly string[];
  policy: NpmProvenancePolicy;
  verifier?: (
    identity: DependencyIdentity,
    verifiedArtifactSha512: string,
    options: NpmProvenanceOptions
  ) => Promise<NpmProvenanceVerification>;
}>;

/** Apply operator trust to the exact archives already hashed by trusted Stage A. */
export async function verifyStageANpmProvenance(
  options: StageANpmProvenanceOptions
): Promise<StageANpmProvenanceResult> {
  const identities = options.identities;
  const digests = options.verifiedArtifactSha512ByLocation;
  if (
    identities.length === 0 ||
    identities.length > 500 ||
    Object.keys(digests).length !== identities.length ||
    identities.some(
      (identity) =>
        identity.ecosystem !== 'npm' ||
        typeof identity.installPath !== 'string' ||
        !Object.hasOwn(digests, identity.installPath) ||
        !/^[a-f0-9]{128}$/u.test(digests[identity.installPath] ?? '')
    )
  )
    throw new Error('Stage A npm artifact identity/digest set is incomplete.');
  const installPaths = new Set(
    identities.map((identity) => identity.installPath)
  );
  if (installPaths.size !== identities.length)
    throw new Error('Stage A npm artifact install paths are ambiguous.');
  const allowedScopes = new Set(options.allowedPublicScopes);
  const verifier =
    options.verifier ?? verifyNpmProvenanceFromVerifiedArtifactSha512;
  const results = await mapConcurrent(identities, 8, async (identity) => {
    const artifactSha512 = digests[identity.installPath as string];
    if (identity.name.startsWith('@')) {
      const scope = identity.name.split('/')[0];
      if (!scope || !allowedScopes.has(scope))
        return {
          status: 'withheld' as const,
          reason: 'private_scope_consent_required'
        };
    }
    return verifier(identity, artifactSha512 as string, {
      policy: options.policy,
      allowPublicScope: identity.name.startsWith('@'),
      requestTimeoutMs: 5000
    });
  });
  const failures = results.filter((result) => result.status !== 'verified');
  return Object.freeze({
    status:
      failures.length === 0
        ? 'verified'
        : failures.some((result) =>
              ['untrusted', 'invalid'].includes(result.status)
            )
          ? 'blocked'
          : 'incomplete',
    artifactCount: identities.length,
    verifiedCount: results.length - failures.length,
    failureCount: failures.length,
    reasonCodes: Object.freeze(
      [...new Set(failures.map((result) => result.reason))].sort()
    )
  });
}
