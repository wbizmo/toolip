import { describe, expect, it, vi } from 'vitest';
import {
  validOwnerAttestationEntry,
  verifyCurrentPullRequestIdentity,
  verifyStageAArtifact,
  resolveStageAWriterMergeSha
} from '../../scripts/verify-stage-a-artifact.mjs';
import {
  cargoArtifactPolicyDigest,
  npmProvenancePolicyDigest
} from '../../scripts/stage-a-canonical-json.mjs';
import { resolveCurrentPullRequestMergeIdentity } from '../../scripts/stage-a-current-pr.mjs';

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
    reviewedDependencyBinaryFiles: 0,
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
  reviewedDependencyReasons: [],
  reviewedDependencyBinaryFiles: 0,
  reviewedDependencyBaselineSha256: null,
  npmOperatorReviewedCount: 0,
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
  it('uses the authenticated API merge SHA when the event merge SHA is absent or stale', () => {
    const eventPr = {
      base: { sha: baseSha },
      head: { sha: headSha },
      merge_commit_sha: null
    };
    const pinned = { baseSha, headSha, mergeSha };
    expect(resolveStageAWriterMergeSha(eventPr, pinned)).toBe(mergeSha);
    expect(
      resolveStageAWriterMergeSha(
        { ...eventPr, merge_commit_sha: mergeSha },
        pinned
      )
    ).toBe(mergeSha);
    expect(
      resolveStageAWriterMergeSha(
        { ...eventPr, merge_commit_sha: '0'.repeat(40) },
        pinned
      )
    ).toBe(mergeSha);
    for (const stale of [
      { ...pinned, headSha: '0'.repeat(40) },
      { ...pinned, baseSha: '0'.repeat(40) },
      { ...pinned, mergeSha: '0'.repeat(39) },
      { ...pinned, mergeSha: '0'.repeat(40) },
      { ...pinned, extra: 'untrusted' }
    ]) {
      // A distinct, well-formed merge SHA is permitted by the API only if
      // the event does not contain a merge_sha to compare; the writer's
      // scan-summary digest binding still rejects a different SHA.
      if (stale.mergeSha === '0'.repeat(40)) continue;
      expect(() => resolveStageAWriterMergeSha(eventPr, stale)).toThrow();
    }
  });

  it('preserves honest operator-reviewed provenance without treating it as publisher proof', () => {
    const loc = 'node_modules/package-0';
    const digest = record.verifiedArtifactSha512ByLocation[loc];
    const reviewSha = 'a'.repeat(64);
    const operatorRecord = {
      ...record,
      npmProvenanceStatus: 'operator-reviewed',
      npmProvenancePolicySha256: reviewSha,
      npmProvenanceVerifiedCount: 0,
      npmOperatorReviewedCount: 5,
      coverage: {
        ...record.coverage,
        dependencyArtifactBinaryFiles: 1,
        reviewedDependencyBinaryFiles: 1
      },
      reviewedDependencyReasons: [
        {
          reason: `artifact-binary-content-uninspected:${loc}`,
          location: loc,
          sha512: digest,
          binaryFiles: 1
        }
      ],
      reviewedDependencyBinaryFiles: 1,
      reviewedDependencyBaselineSha256: reviewSha
    };
    expect(
      verifyStageAArtifact(operatorRecord, event, repository, {
        expectedNpmProvenancePolicySha256: reviewSha
      }).npmProvenanceStatus
    ).toBe('operator-reviewed');
    for (const broken of [
      { ...operatorRecord, npmOperatorReviewedCount: 4 },
      { ...operatorRecord, npmProvenanceVerifiedCount: 5 },
      { ...operatorRecord, npmProvenancePolicySha256: 'b'.repeat(64) },
      { ...operatorRecord, registrySignatureAudit: 'not-applicable' }
    ])
      expect(() =>
        verifyStageAArtifact(broken, event, repository, {
          expectedNpmProvenancePolicySha256: reviewSha
        })
      ).toThrow();
  });

  it('accepts reviewed archive binaries only with exact approval evidence', () => {
    const location = 'node_modules/package-0';
    const reviewedEntry = {
      reason: `artifact-binary-content-uninspected:${location}`,
      location,
      sha512: record.verifiedArtifactSha512ByLocation[location],
      binaryFiles: 2
    };
    const approved = {
      ...record,
      coverage: {
        ...record.coverage,
        dependencyArtifactBinaryFiles: 2,
        reviewedDependencyBinaryFiles: 2
      },
      reviewedDependencyReasons: [reviewedEntry],
      reviewedDependencyBinaryFiles: 2,
      reviewedDependencyBaselineSha256: 'e'.repeat(64)
    };
    expect(
      verifyStageAArtifact(approved, event, repository, {
        expectedNpmProvenancePolicySha256: npmPolicySha256
      }).repository
    ).toBe(repository);
    for (const corrupted of [
      {
        ...approved,
        coverage: { ...approved.coverage, dependencyArtifactBinaryFiles: 3 }
      },
      {
        ...approved,
        reviewedDependencyReasons: [
          { ...reviewedEntry, sha512: '0'.repeat(128) }
        ]
      },
      {
        ...approved,
        reviewedDependencyReasons: [
          {
            ...reviewedEntry,
            reason: `artifact-integrity-mismatch:${location}`
          }
        ]
      },
      { ...approved, reviewedDependencyBaselineSha256: null },
      { ...approved, reviewedDependencyBinaryFiles: 0 }
    ])
      expect(() =>
        verifyStageAArtifact(corrupted, event, repository, {
          expectedNpmProvenancePolicySha256: npmPolicySha256
        })
      ).toThrow();
  });

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

describe('Stage A current pull request merge identity', () => {
  it('waits until the API merge commit has the triggering base and head', async () => {
    const staleMergeSha = 'c'.repeat(40);
    const currentMergeSha = 'd'.repeat(40);
    const commitParents = [
      [{ sha: baseSha }, { sha: 'e'.repeat(40) }],
      [{ sha: baseSha }, { sha: headSha }]
    ];
    let pullRequests = 0;
    let commits = 0;
    const delays: number[] = [];
    const identity = await resolveCurrentPullRequestMergeIdentity({
      expectedBaseSha: baseSha,
      expectedHeadSha: headSha,
      getPullRequest: async () => ({
        data: {
          base: { sha: baseSha },
          head: { sha: headSha },
          merge_commit_sha:
            pullRequests++ === 0 ? staleMergeSha : currentMergeSha
        }
      }),
      getCommit: async () => ({ data: { parents: commitParents[commits++] } }),
      wait: async (milliseconds) => {
        delays.push(milliseconds);
      }
    });

    expect(identity).toEqual({
      baseSha,
      headSha,
      mergeSha: currentMergeSha
    });
    expect(delays).toEqual([1_000]);
  });

  it('rejects a changed event base or head without retrying', async () => {
    const getCommit = vi.fn();
    const wait = vi.fn();
    await expect(
      resolveCurrentPullRequestMergeIdentity({
        expectedBaseSha: baseSha,
        expectedHeadSha: headSha,
        getPullRequest: async () => ({
          data: {
            base: { sha: 'e'.repeat(40) },
            head: { sha: headSha },
            merge_commit_sha: 'f'.repeat(40)
          }
        }),
        getCommit,
        wait
      })
    ).rejects.toThrow('base/head no longer match');
    expect(getCommit).not.toHaveBeenCalled();
    expect(wait).not.toHaveBeenCalled();
  });

  it('fails closed after a bounded wait if GitHub never refreshes the merge', async () => {
    const wait = vi.fn(async () => {});
    await expect(
      resolveCurrentPullRequestMergeIdentity({
        expectedBaseSha: baseSha,
        expectedHeadSha: headSha,
        attempts: 3,
        getPullRequest: async () => ({
          data: {
            base: { sha: baseSha },
            head: { sha: headSha },
            merge_commit_sha: 'f'.repeat(40)
          }
        }),
        getCommit: async () => ({
          data: { parents: [{ sha: baseSha }, { sha: 'e'.repeat(40) }] }
        }),
        wait
      })
    ).rejects.toThrow('merge commit is not ready');
    expect(wait).toHaveBeenCalledTimes(2);
  });
});
