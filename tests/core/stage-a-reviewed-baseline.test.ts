import { describe, expect, it } from 'vitest';
import {
  parseStageAReviewedDependencyPolicy,
  applyStageAReviewedDependencyPolicy,
  verifyStageAReviewedDependencyEvidence,
  verifyStageAOperatorReviewedRegistryGraph
} from '../../scripts/stage-a-reviewed-baseline.mjs';

const repository = 'wbizmo/toolip';
const sha512 = 'a'.repeat(128);
const location = 'node_modules/@biomejs/cli-linux-x64';
const reason = `artifact-binary-content-uninspected:${location}`;
const now = Date.parse('2026-11-23T02:00:00.000Z');
const issuedAt = '2026-11-23T00:00:00.000Z';
const expiresAt = '2026-11-29T00:00:00.000Z';
const lockSha = 'b'.repeat(64);
const entry = { reason, location, sha512 };
const policy = {
  version: 1,
  repository,
  issuedAt,
  expiresAt,
  lockfileSha256: lockSha,
  entries: [entry]
};

describe('protected-base dependency review', () => {
  it('reviews only an exact verified archive uncertainty and counts its binary members', () => {
    const parsed = parseStageAReviewedDependencyPolicy(
      JSON.stringify(policy),
      now
    );
    expect(parsed.invalid).toBe(false);
    const result = applyStageAReviewedDependencyPolicy({
      parsed,
      repository,
      currentLockfileSha256: lockSha,
      baseLockfileSha256: lockSha,
      changedArtifactCount: 0,
      reasons: [reason, 'artifact-fetch-unavailable:node_modules/missing'],
      verifiedArtifactSha512ByLocation: { [location]: sha512 },
      verifiedBinaryFilesByLocation: { [location]: 2 }
    });
    expect(result.remainingReasons).toEqual([
      'artifact-fetch-unavailable:node_modules/missing'
    ]);
    expect(result.reviewedBinaryFiles).toBe(2);
    expect(result.reviewedReasons).toHaveLength(1);
    expect(
      verifyStageAReviewedDependencyEvidence({
        ...result,
        coverage: {
          dependencyArtifactBinaryFiles: 2,
          reviewedDependencyBinaryFiles: 2
        },
        verifiedArtifactSha512ByLocation: { [location]: sha512 }
      })
    ).toBe(true);
  });

  it('rejects ambiguous duplicate-key operator approval documents', () => {
    const raw = JSON.stringify(policy).replace(
      '"version":1',
      '"version":1,"version":1'
    );
    expect(parseStageAReviewedDependencyPolicy(raw, now).invalid).toBe(true);
  });

  it('fails closed for expired, malformed, overlong or wildcard approvals', () => {
    for (const broken of [
      { ...policy, expiresAt: '2026-12-29T00:00:00.000Z' },
      { ...policy, entries: [{ ...entry, location: 'node_modules/*' }] },
      {
        ...policy,
        entries: [
          { ...entry, reason: `artifact-integrity-mismatch:${location}` }
        ]
      },
      { ...policy, entries: [{ ...entry, sha512: '0'.repeat(128) }] },
      { ...policy, entries: [entry, entry] }
    ]) {
      const parsed = parseStageAReviewedDependencyPolicy(
        JSON.stringify(broken),
        now
      );
      const input = {
        parsed,
        repository,
        currentLockfileSha256: lockSha,
        baseLockfileSha256: lockSha,
        changedArtifactCount: 0,
        reasons: [reason],
        verifiedArtifactSha512ByLocation: { [location]: sha512 },
        verifiedBinaryFilesByLocation: { [location]: 1 }
      };
      const evaluated = applyStageAReviewedDependencyPolicy(input);
      expect(evaluated.remainingReasons.length).toBeGreaterThan(0);
    }
  });

  it('binds registry-provenance fallback to every unchanged locked artifact digest', () => {
    const full = {
      ...policy,
      reviewedRegistryArchives: {
        [location]: sha512,
        'node_modules/clean': 'c'.repeat(128)
      }
    };
    const parsed = parseStageAReviewedDependencyPolicy(
      JSON.stringify(full),
      now
    );
    expect(parsed.invalid).toBe(false);
    const graph = {
      parsed,
      repository,
      currentLockfileSha256: lockSha,
      baseLockfileSha256: lockSha,
      changedArtifactCount: 0,
      verifiedArtifactSha512ByLocation: {
        [location]: sha512,
        'node_modules/clean': 'c'.repeat(128)
      }
    };
    expect(verifyStageAOperatorReviewedRegistryGraph(graph)).toMatchObject({
      status: 'operator-reviewed',
      artifactCount: 2,
      provenanceVerifiedCount: 0,
      operatorReviewedCount: 2
    });
    for (const invalid of [
      { changedArtifactCount: 1 },
      { currentLockfileSha256: 'f'.repeat(64) },
      { verifiedArtifactSha512ByLocation: { [location]: sha512 } },
      {
        verifiedArtifactSha512ByLocation: {
          ...graph.verifiedArtifactSha512ByLocation,
          [location]: 'f'.repeat(128)
        }
      }
    ])
      expect(
        verifyStageAOperatorReviewedRegistryGraph({ ...graph, ...invalid })
      ).toBeUndefined();
  });

  it('does not accept a changed lock, changed artifact, unverified digest or forged artifact report', () => {
    const parsed = parseStageAReviewedDependencyPolicy(
      JSON.stringify(policy),
      now
    );
    const common = {
      parsed,
      repository,
      currentLockfileSha256: lockSha,
      baseLockfileSha256: lockSha,
      changedArtifactCount: 0,
      reasons: [reason],
      verifiedArtifactSha512ByLocation: { [location]: sha512 },
      verifiedBinaryFilesByLocation: { [location]: 1 }
    };
    for (const changed of [
      { currentLockfileSha256: 'c'.repeat(64) },
      { baseLockfileSha256: 'c'.repeat(64) },
      { changedArtifactCount: 1 },
      { verifiedArtifactSha512ByLocation: { [location]: 'c'.repeat(128) } },
      { verifiedBinaryFilesByLocation: { [location]: 0 } }
    ]) {
      const evaluated = applyStageAReviewedDependencyPolicy({
        ...common,
        ...changed
      });
      expect(evaluated.remainingReasons).toContain(reason);
    }
    const good = applyStageAReviewedDependencyPolicy(common);
    expect(
      verifyStageAReviewedDependencyEvidence({
        ...good,
        coverage: {
          dependencyArtifactBinaryFiles: 3,
          reviewedDependencyBinaryFiles: 1
        },
        verifiedArtifactSha512ByLocation: { [location]: sha512 }
      })
    ).toBe(false);
  });
});
