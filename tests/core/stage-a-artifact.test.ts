import { describe, expect, it } from 'vitest';
import {
  validOwnerAttestationEntry,
  verifyCurrentPullRequestIdentity,
  verifyStageAArtifact
} from '../../scripts/verify-stage-a-artifact.mjs';
import {
  cargoArtifactPolicyDigest,
  npmProvenancePolicyDigest
} from '../../scripts/stage-a-canonical-json.mjs';

const repository = 'wbizmo/toolip';
const baseSha = 'a'.repeat(40);
const headSha = 'b'.repeat(40);
const mergeSha = 'c'.repeat(40);
const npmPolicyText = JSON.stringify({
  version: 1,
  packages: {
    widget: {
      certificateIssuer: 'https://token.actions.githubusercontent.com',
      certificateIdentity: 'https://github.com/acme/widget/release.yml',
      sourceRepository: 'https://github.com/acme/widget'
    }
  }
});
const npmPolicySha256 = npmProvenancePolicyDigest(npmPolicyText);
const cargoPolicyText = JSON.stringify({
  version: 1,
  packages: { 'safe-crate@1.2.3': 'a'.repeat(64) }
});
const cargoPolicySha256 = cargoArtifactPolicyDigest(cargoPolicyText);
const complexityBody = `## Algorithmic analysis\nPrevious worst-case time: O(n^2)\nNew worst-case time: O(n log n)\nPrevious peak space: O(n)\nNew peak space: O(n)`;
const record = {
  version: 7,
  repository,
  pullRequest: 123,
  runId: '456',
  baseSha,
  baseRef: 'main',
  headSha,
  mergeSha,
  scannerSha256: 'd'.repeat(64),
  inputSha256: 'e'.repeat(64),
  headInputSha256: 'f'.repeat(64),
  coverage: {
    changedFiles: 1,
    head: { files: 10, textFiles: 9, bytes: 100 },
    merge: { files: 11, textFiles: 10, bytes: 110 },
    dependencyArtifactsChecked: 5,
    dependencyArtifactsChanged: 3,
    dependencyArtifactCount: 5,
    dependencyArtifactFiles: 10,
    dependencyArtifactBytes: 1000,
    dependencyArtifactNetworkBytes: 500,
    dependencyArtifactBinaryFiles: 0,
    nonNpmDependencyArtifactsChecked: 0,
    nonNpmDependencyArtifactCount: 0,
    cargoDependencyArtifactCount: 0,
    goDependencyArtifactCount: 0,
    nonNpmDependencyArtifactFiles: 0,
    nonNpmDependencyArtifactBytes: 0,
    nonNpmDependencyArtifactNetworkBytes: 0,
    nonNpmDependencyArtifactBinaryFiles: 0,
    headCommitSignatureStatus: 'verified'
  },
  exceptionPolicySha256: null,
  appliedExceptions: [],
  registrySignatureAudit: 'verified',
  npmProvenanceStatus: 'verified',
  npmProvenancePolicySha256: npmPolicySha256,
  npmProvenanceArtifactCount: 5,
  npmProvenanceVerifiedCount: 5,
  verifiedArtifactSha512ByLocation: Object.fromEntries(
    Array.from({ length: 5 }, (_, index) => [
      `node_modules/package-${index}`,
      String(index + 1).padStart(128, '0')
    ])
  ),
  verifiedArtifactSha256ByLocation: {},
  cargoArtifactPolicySha256: null,
  reasonCodes: [],
  status: 'approved',
  complexityEvidence: true
};
const event = {
  repository: { full_name: repository },
  workflow_run: {
    id: 456,
    event: 'pull_request_target',
    conclusion: 'success',
    name: 'Stage A Trusted Pre-execution Gate',
    repository: { full_name: repository },
    pull_requests: [
      {
        number: 123,
        base: { sha: baseSha, ref: 'main' },
        head: { sha: headSha },
        merge_commit_sha: mergeSha
      }
    ]
  }
};

describe('Stage A artifact identity verification', () => {
  it('validates exact digest-bound owner attestations in an immutable approval', () => {
    const start = new Date(Date.now() - 60_000).toISOString();
    const end = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const reason =
      'unsupported-toolchain-execution:artifact:node_modules/package-0/bin/tool:node_modules/package-0';
    const entry = {
      id: 'owner-reviewed-artifact',
      reasonCode: 'unsupported-toolchain-execution',
      exactReason: reason,
      headInputSha256: record.headInputSha256,
      expiresAt: end,
      reviewer: 'wbizmo',
      reviewedAt: start,
      reviewedCommit: headSha,
      ownerAttestation: {
        owner: 'wbizmo',
        headSha,
        attestedAt: start,
        artifactLocation: 'node_modules/package-0',
        artifactSha512:
          record.verifiedArtifactSha512ByLocation['node_modules/package-0']
      }
    };
    const approved = { ...record, appliedExceptions: [entry] };
    expect(validOwnerAttestationEntry(entry, approved)).toBe(true);
    expect(
      verifyStageAArtifact(approved, event, repository, {
        expectedNpmProvenancePolicySha256: npmPolicySha256
      }).appliedExceptions
    ).toHaveLength(1);
    for (const changed of [
      {
        ...entry,
        exactReason: 'unsupported-toolchain-execution:node_modules/other'
      },
      { ...entry, reviewer: 'intruder' },
      {
        ...entry,
        ownerAttestation: {
          ...entry.ownerAttestation,
          artifactSha512: 'a'.repeat(128)
        }
      },
      {
        ...entry,
        ownerAttestation: { ...entry.ownerAttestation, headSha: '0'.repeat(40) }
      },
      {
        ...entry,
        expiresAt: new Date(Date.now() + 9 * 24 * 60 * 60 * 1000).toISOString()
      }
    ]) {
      expect(validOwnerAttestationEntry(changed, approved)).toBe(false);
      expect(() =>
        verifyStageAArtifact(
          { ...approved, appliedExceptions: [changed] },
          event,
          repository,
          { expectedNpmProvenancePolicySha256: npmPolicySha256 }
        )
      ).toThrow();
    }
  });

  it('accepts only an approved artifact bound to its successful PR run and exact commits', () => {
    expect(
      verifyStageAArtifact(record, event, repository, {
        expectedNpmProvenancePolicySha256: npmPolicySha256
      })
    ).toEqual({
      repository,
      pullRequest: 123,
      baseSha,
      baseRef: 'main',
      headSha,
      mergeSha,
      complexityEvidence: true,
      registrySignatureAudit: 'verified',
      npmProvenanceStatus: 'verified',
      npmProvenancePolicySha256: npmPolicySha256,
      npmProvenanceArtifactCount: 5,
      npmProvenanceVerifiedCount: 5,
      verifiedArtifactSha512ByLocation: record.verifiedArtifactSha512ByLocation,
      verifiedArtifactSha256ByLocation: record.verifiedArtifactSha256ByLocation,
      cargoArtifactPolicySha256: null,
      coverage: record.coverage,
      exceptionPolicySha256: null,
      appliedExceptions: []
    });
  });

  it('retains exact-tree exception policy and review identity in the audit artifact', () => {
    const exception = {
      id: 'reviewed-false-positive',
      findingId: '1'.repeat(64),
      headInputSha256: record.headInputSha256,
      expiresAt: '2026-12-01T00:00:00.000Z',
      reviewer: 'maintainer',
      reviewedAt: '2026-11-06T10:00:00.000Z',
      reviewedCommit: headSha
    };
    const result = verifyStageAArtifact(
      {
        ...record,
        exceptionPolicySha256: '2'.repeat(64),
        appliedExceptions: [exception]
      },
      event,
      repository,
      { expectedNpmProvenancePolicySha256: npmPolicySha256 }
    );
    expect(result.exceptionPolicySha256).toBe('2'.repeat(64));
    expect(result.appliedExceptions).toEqual([exception]);
  });

  it('rejects another run, repository, pull request or commit snapshot', () => {
    for (const changed of [
      { ...record, version: 2 },
      { ...record, version: 6 },
      { ...record, runId: '999' },
      { ...record, repository: 'attacker/fork' },
      { ...record, headSha: 'd'.repeat(40) },
      { ...record, status: 'incomplete' },
      { ...record, scannerSha256: 'bad' },
      { ...record, registrySignatureAudit: 'not-applicable' },
      { ...record, npmProvenanceStatus: 'incomplete' },
      { ...record, npmProvenancePolicySha256: null },
      {
        ...record,
        verifiedArtifactSha512ByLocation: {
          ...record.verifiedArtifactSha512ByLocation,
          'node_modules/../../escape': '2'.repeat(128)
        }
      },
      {
        ...record,
        coverage: {
          ...record.coverage,
          dependencyArtifactsChecked: 4
        }
      },
      {
        ...record,
        verifiedArtifactSha256ByLocation: {
          'cargo-lock/../Cargo.lock/serde@1.0.0': '2'.repeat(64)
        }
      },
      {
        ...record,
        coverage: {
          ...record.coverage,
          merge: { ...record.coverage.merge, bytes: -1 }
        }
      },
      {
        ...record,
        coverage: {
          ...record.coverage,
          headCommitSignatureStatus: 'unavailable'
        }
      },
      {
        ...record,
        appliedExceptions: [
          {
            id: 'unbound',
            findingId: 'a'.repeat(64),
            headInputSha256: '0'.repeat(64),
            expiresAt: '2026-12-01T00:00:00.000Z',
            reviewer: 'maintainer',
            reviewedAt: '2026-11-06T10:00:00.000Z',
            reviewedCommit: headSha
          }
        ]
      }
    ])
      expect(() =>
        verifyStageAArtifact(changed, event, repository, {
          expectedNpmProvenancePolicySha256: npmPolicySha256
        })
      ).toThrow('does not match');
  });

  it('rejects workflow runs without a matching pull request snapshot', () => {
    expect(() =>
      verifyStageAArtifact(
        record,
        {
          ...event,
          workflow_run: { ...event.workflow_run, pull_requests: [] }
        },
        repository,
        { expectedNpmProvenancePolicySha256: npmPolicySha256 }
      )
    ).toThrow('does not match');
  });

  it('rejects stale or missing current provenance policy for dependency-bearing approvals', () => {
    expect(npmPolicySha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(npmProvenancePolicyDigest(npmPolicyText)).toBe(npmPolicySha256);
    const reorderedPolicy = JSON.stringify({
      packages: {
        widget: {
          sourceRepository: 'https://github.com/acme/widget',
          certificateIdentity: 'https://github.com/acme/widget/release.yml',
          certificateIssuer: 'https://token.actions.githubusercontent.com'
        }
      },
      version: 1
    });
    expect(npmProvenancePolicyDigest(reorderedPolicy)).toBe(npmPolicySha256);
    expect(
      verifyStageAArtifact(record, event, repository, {
        expectedNpmProvenancePolicySha256: npmPolicySha256
      }).npmProvenancePolicySha256
    ).toBe(npmPolicySha256);
    expect(() =>
      verifyStageAArtifact(record, event, repository, {
        expectedNpmProvenancePolicySha256: '2'.repeat(64)
      })
    ).toThrow('does not match');
    expect(() => verifyStageAArtifact(record, event, repository)).toThrow(
      'does not match'
    );
    expect(() =>
      npmProvenancePolicyDigest('{"version":1,"version":1,"packages":{}}')
    ).toThrow('invalid');
    expect(() => npmProvenancePolicyDigest('{')).toThrow('invalid');
    expect(() =>
      npmProvenancePolicyDigest(`${'['.repeat(80)}0${']'.repeat(80)}`)
    ).toThrow('invalid');
    expect(() =>
      npmProvenancePolicyDigest('x'.repeat(1024 * 1024 + 1))
    ).toThrow('unavailable');
  });

  it('does not require npm policy when the trusted scan found no npm artifacts', () => {
    const noDependencies = {
      ...record,
      coverage: {
        ...record.coverage,
        dependencyArtifactsChecked: 0,
        dependencyArtifactsChanged: 0,
        dependencyArtifactCount: 0
      },
      registrySignatureAudit: 'not-applicable',
      npmProvenanceStatus: 'not-applicable',
      npmProvenancePolicySha256: null,
      npmProvenanceArtifactCount: 0,
      npmProvenanceVerifiedCount: 0,
      verifiedArtifactSha512ByLocation: {},
      verifiedArtifactSha256ByLocation: {}
    };
    expect(
      verifyStageAArtifact(noDependencies, event, repository)
        .npmProvenanceStatus
    ).toBe('not-applicable');
  });

  it('binds scanned Cargo artifacts to the current operator-owned digest policy', () => {
    const location = `cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3#${'a'.repeat(64)}`;
    const cargoRecord = {
      ...record,
      coverage: {
        ...record.coverage,
        nonNpmDependencyArtifactsChecked: 1,
        nonNpmDependencyArtifactCount: 1,
        cargoDependencyArtifactCount: 1
      },
      cargoArtifactPolicySha256: cargoPolicySha256,
      verifiedArtifactSha256ByLocation: { [location]: 'a'.repeat(64) }
    };
    expect(
      verifyStageAArtifact(cargoRecord, event, repository, {
        expectedNpmProvenancePolicySha256: npmPolicySha256,
        expectedCargoArtifactPolicySha256: cargoPolicySha256
      }).cargoArtifactPolicySha256
    ).toBe(cargoPolicySha256);
    expect(() =>
      verifyStageAArtifact(cargoRecord, event, repository, {
        expectedNpmProvenancePolicySha256: npmPolicySha256,
        expectedCargoArtifactPolicySha256: 'b'.repeat(64)
      })
    ).toThrow('does not match');
  });

  it('accepts verified Go artifacts without requiring a Cargo-only policy', () => {
    const location = `go-module/Z28ubW9k/ZXhhbXBsZS50ZXN0L2xpYg@djEuMi4z#${'a'.repeat(64)}`;
    const goRecord = {
      ...record,
      coverage: {
        ...record.coverage,
        nonNpmDependencyArtifactsChecked: 1,
        nonNpmDependencyArtifactCount: 1,
        goDependencyArtifactCount: 1
      },
      verifiedArtifactSha256ByLocation: { [location]: 'b'.repeat(64) }
    };
    expect(
      verifyStageAArtifact(goRecord, event, repository, {
        expectedNpmProvenancePolicySha256: npmPolicySha256
      }).cargoArtifactPolicySha256
    ).toBeNull();
  });

  it('rejects malformed and duplicate-key Cargo artifact policies', () => {
    expect(cargoArtifactPolicyDigest(cargoPolicyText)).toBe(cargoPolicySha256);
    expect(() =>
      cargoArtifactPolicyDigest(
        '{"version":1,"version":1,"packages":{"safe-crate@1.2.3":"' +
          'a'.repeat(64) +
          '"}}'
      )
    ).toThrow('invalid');
    expect(() =>
      cargoArtifactPolicyDigest(
        JSON.stringify({ version: 1, packages: { 'safe-crate@1.2.3': 'bad' } })
      )
    ).toThrow('invalid');
  });

  it('rechecks the current PR identity before any Stage B work starts', () => {
    const current = {
      number: 123,
      state: 'open',
      body: complexityBody,
      base: { repo: { full_name: repository }, ref: 'main', sha: baseSha },
      head: { sha: headSha },
      merge_commit_sha: mergeSha
    };
    expect(verifyCurrentPullRequestIdentity(record, repository, current)).toBe(
      true
    );
    for (const stale of [
      { ...current, head: { sha: 'd'.repeat(40) } },
      { ...current, base: { ...current.base, sha: 'e'.repeat(40) } },
      { ...current, merge_commit_sha: 'f'.repeat(40) },
      { ...current, state: 'closed' },
      { ...current, body: 'removed complexity disclosure' }
    ]) {
      expect(() =>
        verifyCurrentPullRequestIdentity(record, repository, stale)
      ).toThrow('stale');
    }
    expect(() =>
      verifyCurrentPullRequestIdentity(record, repository, undefined)
    ).toThrow('stale');
  });
});
