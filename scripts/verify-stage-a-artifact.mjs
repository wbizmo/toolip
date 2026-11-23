#!/usr/bin/env node
import { appendFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  cargoArtifactPolicyDigest,
  npmProvenancePolicyDigest
} from './stage-a-canonical-json.mjs';
import { verifyStageAReviewedDependencyEvidence } from './stage-a-reviewed-baseline.mjs';

function complexityEvidence(body) {
  const text = typeof body === 'string' ? body.toLowerCase() : '';
  return (
    [
      '## algorithmic analysis',
      'previous worst-case time',
      'new worst-case time',
      'previous peak space',
      'new peak space'
    ].every((section) => text.includes(section)) &&
    /O\([^)]*\)|N\/A/iu.test(text)
  );
}

const OWNER_ATTESTABLE_ARTIFACT_REASONS = new Set([
  'artifact-binary-content-uninspected',
  'dependency-lifecycle-script-review',
  'dynamic-command-resolution',
  'unresolved-child-process-execution',
  'unsupported-toolchain-execution',
  'unverified-npm-resolution'
]);

/** Rejects forged, broad or expired owner attestations even in an approval record. */
export function validOwnerAttestationEntry(entry, record, now = Date.now()) {
  if (!entry || typeof entry !== 'object') return false;
  if (!entry.ownerAttestation) return entry.exactReason === undefined;
  const attestation = entry.ownerAttestation;
  const owner = record?.repository?.split('/');
  const location = attestation.artifactLocation;
  const attestedAt = Date.parse(attestation.attestedAt);
  const expiresAt = Date.parse(entry.expiresAt);
  return (
    owner?.length === 2 &&
    typeof attestation.owner === 'string' &&
    attestation.owner.toLowerCase() === owner[0].toLowerCase() &&
    OWNER_ATTESTABLE_ARTIFACT_REASONS.has(entry.reasonCode) &&
    typeof entry.exactReason === 'string' &&
    entry.exactReason.startsWith(`${entry.reasonCode}:`) &&
    entry.exactReason.length <= 768 &&
    typeof location === 'string' &&
    location.length <= 256 &&
    /^node_modules\/(?:[A-Za-z0-9@._-]+\/)*[A-Za-z0-9._-]+$/u.test(location) &&
    !location
      .split('/')
      .some((segment) => segment === '.' || segment === '..') &&
    entry.exactReason.endsWith(`:${location}`) &&
    /^[a-f0-9]{128}$/u.test(attestation.artifactSha512 ?? '') &&
    record?.verifiedArtifactSha512ByLocation?.[location] ===
      attestation.artifactSha512 &&
    attestation.headSha === record.headSha &&
    entry.headInputSha256 === record.headInputSha256 &&
    entry.reviewer === attestation.owner &&
    entry.reviewedAt === attestation.attestedAt &&
    entry.reviewedCommit === attestation.headSha &&
    Number.isFinite(attestedAt) &&
    Number.isFinite(expiresAt) &&
    new Date(attestedAt).toISOString() === attestation.attestedAt &&
    attestedAt <= now &&
    expiresAt > now &&
    expiresAt <= attestedAt + 7 * 24 * 60 * 60 * 1000
  );
}

/**
 * pull_request_target payloads may omit merge_commit_sha when a PR is new.
 * The Stage A job separately fetches the current immutable merge identity via
 * GitHub API before scanning. Reuse the exact API snapshot at artifact writing.
 * Reject stale base/head and malformed identity. GitHub can refresh the
 * synthetic merge commit after the pull_request_target event was emitted, so
 * the authenticated API merge SHA is authoritative when it is bound to the
 * event's unchanged base and head.
 */
export function resolveStageAWriterMergeSha(pr, apiIdentity) {
  const validSha = (value) => /^[a-f0-9]{40}$/u.test(value ?? '');
  if (
    !pr ||
    !apiIdentity ||
    typeof apiIdentity !== 'object' ||
    Array.isArray(apiIdentity) ||
    Object.keys(apiIdentity).sort().join(',') !== 'baseSha,headSha,mergeSha' ||
    !validSha(pr.base?.sha) ||
    !validSha(pr.head?.sha) ||
    !validSha(apiIdentity.baseSha) ||
    !validSha(apiIdentity.headSha) ||
    !validSha(apiIdentity.mergeSha) ||
    apiIdentity.baseSha !== pr.base.sha ||
    apiIdentity.headSha !== pr.head.sha
  )
    throw new Error(
      'Stage A current pull request merge identity is invalid or stale'
    );
  return apiIdentity.mergeSha;
}

export function verifyStageAArtifact(
  record,
  event,
  expectedRepository,
  { expectedNpmProvenancePolicySha256, expectedCargoArtifactPolicySha256 } = {}
) {
  const run = event?.workflow_run;
  const associatedPrs = Array.isArray(run?.pull_requests)
    ? run.pull_requests.filter((pr) => pr?.number === record?.pullRequest)
    : [];
  const pr = associatedPrs[0];
  const nonnegativeSafeInteger = (value) =>
    Number.isSafeInteger(value) && value >= 0;
  if (
    record?.version !== 7 ||
    record.status !== 'approved' ||
    record.repository !== expectedRepository ||
    event?.repository?.full_name !== expectedRepository ||
    run?.repository?.full_name !== expectedRepository ||
    record.runId !== String(run?.id) ||
    run?.event !== 'pull_request_target' ||
    run?.conclusion !== 'success' ||
    run?.name !== 'Stage A Trusted Pre-execution Gate' ||
    typeof record.complexityEvidence !== 'boolean' ||
    !Number.isSafeInteger(record.pullRequest) ||
    associatedPrs.length !== 1 ||
    pr?.base?.sha !== record.baseSha ||
    record.baseRef !== 'main' ||
    pr?.base?.ref !== record.baseRef ||
    pr?.head?.sha !== record.headSha ||
    (pr?.merge_commit_sha !== undefined &&
      pr.merge_commit_sha !== record.mergeSha) ||
    !/^[0-9a-f]{64}$/iu.test(record.scannerSha256 ?? '') ||
    !/^[0-9a-f]{64}$/iu.test(record.inputSha256 ?? '') ||
    !/^[0-9a-f]{64}$/iu.test(record.headInputSha256 ?? '') ||
    !(
      record.exceptionPolicySha256 === null ||
      /^[0-9a-f]{64}$/iu.test(record.exceptionPolicySha256 ?? '')
    ) ||
    !(record.coverage?.cargoDependencyArtifactCount > 0
      ? /^[0-9a-f]{64}$/iu.test(record.cargoArtifactPolicySha256 ?? '') &&
        typeof expectedCargoArtifactPolicySha256 === 'string' &&
        record.cargoArtifactPolicySha256 === expectedCargoArtifactPolicySha256
      : record.cargoArtifactPolicySha256 === null) ||
    !Array.isArray(record.appliedExceptions) ||
    record.appliedExceptions.length > 100 ||
    record.appliedExceptions.some(
      (entry) =>
        !entry ||
        typeof entry !== 'object' ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(entry.id ?? '') ||
        (typeof entry.findingId === 'string') ===
          (typeof entry.reasonCode === 'string') ||
        (entry.findingId !== undefined &&
          !/^[a-f0-9]{64}$/u.test(entry.findingId)) ||
        (entry.reasonCode !== undefined &&
          !/^[a-z0-9][a-z0-9-]{0,63}$/u.test(entry.reasonCode)) ||
        entry.headInputSha256 !== record.headInputSha256 ||
        !Number.isFinite(Date.parse(entry.expiresAt)) ||
        new Date(Date.parse(entry.expiresAt)).toISOString() !==
          entry.expiresAt ||
        Date.parse(entry.expiresAt) <= Date.now() ||
        typeof entry.reviewer !== 'string' ||
        !/^[A-Za-z0-9-]{1,39}$/u.test(entry.reviewer) ||
        !Number.isFinite(Date.parse(entry.reviewedAt)) ||
        entry.reviewedCommit !== record.headSha ||
        !validOwnerAttestationEntry(entry, record)
    ) ||
    !Array.isArray(record.reasonCodes) ||
    record.reasonCodes.length !== 0 ||
    !nonnegativeSafeInteger(record.coverage?.changedFiles) ||
    !nonnegativeSafeInteger(record.coverage?.head?.files) ||
    !nonnegativeSafeInteger(record.coverage?.head?.textFiles) ||
    !nonnegativeSafeInteger(record.coverage?.head?.bytes) ||
    !nonnegativeSafeInteger(record.coverage?.merge?.files) ||
    !nonnegativeSafeInteger(record.coverage?.merge?.textFiles) ||
    !nonnegativeSafeInteger(record.coverage?.merge?.bytes) ||
    !nonnegativeSafeInteger(record.coverage?.dependencyArtifactsChecked) ||
    !nonnegativeSafeInteger(record.coverage?.dependencyArtifactsChanged) ||
    !nonnegativeSafeInteger(record.coverage?.dependencyArtifactCount) ||
    !nonnegativeSafeInteger(record.coverage?.dependencyArtifactFiles) ||
    !nonnegativeSafeInteger(record.coverage?.dependencyArtifactBytes) ||
    !nonnegativeSafeInteger(record.coverage?.dependencyArtifactNetworkBytes) ||
    !nonnegativeSafeInteger(record.coverage?.dependencyArtifactBinaryFiles) ||
    !nonnegativeSafeInteger(
      record.coverage?.nonNpmDependencyArtifactsChecked
    ) ||
    !nonnegativeSafeInteger(record.coverage?.nonNpmDependencyArtifactCount) ||
    !nonnegativeSafeInteger(record.coverage?.cargoDependencyArtifactCount) ||
    !nonnegativeSafeInteger(record.coverage?.goDependencyArtifactCount) ||
    !nonnegativeSafeInteger(record.coverage?.nonNpmDependencyArtifactFiles) ||
    !nonnegativeSafeInteger(record.coverage?.nonNpmDependencyArtifactBytes) ||
    !nonnegativeSafeInteger(
      record.coverage?.nonNpmDependencyArtifactNetworkBytes
    ) ||
    !nonnegativeSafeInteger(
      record.coverage?.nonNpmDependencyArtifactBinaryFiles
    ) ||
    !['verified', 'unverified'].includes(
      record.coverage?.headCommitSignatureStatus
    ) ||
    record.coverage.dependencyArtifactsChecked >
      record.coverage.dependencyArtifactCount ||
    record.coverage.dependencyArtifactsChanged >
      record.coverage.dependencyArtifactCount ||
    record.coverage.dependencyArtifactsChecked !==
      record.coverage.dependencyArtifactCount ||
    !verifyStageAReviewedDependencyEvidence({
      reviewedReasons: record.reviewedDependencyReasons,
      reviewedBinaryFiles: record.reviewedDependencyBinaryFiles,
      baselineSha256: record.reviewedDependencyBaselineSha256,
      coverage: record.coverage,
      verifiedArtifactSha512ByLocation: record.verifiedArtifactSha512ByLocation
    }) ||
    record.coverage.nonNpmDependencyArtifactsChecked !==
      record.coverage.nonNpmDependencyArtifactCount ||
    record.coverage.cargoDependencyArtifactCount +
      record.coverage.goDependencyArtifactCount !==
      record.coverage.nonNpmDependencyArtifactCount ||
    record.coverage.nonNpmDependencyArtifactBinaryFiles !== 0 ||
    record.registrySignatureAudit !==
      (record.coverage.dependencyArtifactCount > 0
        ? 'verified'
        : 'not-applicable') ||
    !(record.coverage.dependencyArtifactCount > 0
      ? ['verified', 'operator-reviewed'].includes(record.npmProvenanceStatus)
      : record.npmProvenanceStatus === 'not-applicable') ||
    !(record.coverage.dependencyArtifactCount > 0
      ? /^[0-9a-f]{64}$/iu.test(record.npmProvenancePolicySha256 ?? '')
      : record.npmProvenancePolicySha256 === null) ||
    record.npmProvenanceArtifactCount !==
      record.coverage.dependencyArtifactCount ||
    (record.npmProvenanceStatus === 'verified'
      ? record.npmProvenanceVerifiedCount !==
          record.coverage.dependencyArtifactCount ||
        (record.npmOperatorReviewedCount ?? 0) !== 0
      : record.npmProvenanceStatus === 'operator-reviewed'
        ? record.npmProvenanceVerifiedCount !== 0 ||
          record.npmOperatorReviewedCount !==
            record.coverage.dependencyArtifactCount ||
          record.npmProvenancePolicySha256 !==
            record.reviewedDependencyBaselineSha256
        : record.npmProvenanceVerifiedCount !== 0 ||
          (record.npmOperatorReviewedCount ?? 0) !== 0) ||
    (record.coverage.dependencyArtifactCount > 0 &&
      (typeof expectedNpmProvenancePolicySha256 !== 'string' ||
        record.npmProvenancePolicySha256 !==
          expectedNpmProvenancePolicySha256)) ||
    !record.verifiedArtifactSha512ByLocation ||
    typeof record.verifiedArtifactSha512ByLocation !== 'object' ||
    Array.isArray(record.verifiedArtifactSha512ByLocation) ||
    Object.keys(record.verifiedArtifactSha512ByLocation).length !==
      record.coverage.dependencyArtifactCount ||
    Object.entries(record.verifiedArtifactSha512ByLocation).some(
      ([location, digest]) =>
        !/^node_modules\/(?!.*(?:^|\/)\.\.(?:\/|$))[^\\\0]+$/u.test(location) ||
        !/^[a-f0-9]{128}$/iu.test(digest ?? '')
    ) ||
    !record.verifiedArtifactSha256ByLocation ||
    typeof record.verifiedArtifactSha256ByLocation !== 'object' ||
    Array.isArray(record.verifiedArtifactSha256ByLocation) ||
    Object.keys(record.verifiedArtifactSha256ByLocation).length !==
      record.coverage.nonNpmDependencyArtifactCount ||
    Object.entries(record.verifiedArtifactSha256ByLocation).some(
      ([location, digest]) =>
        !/^(?:cargo-lock\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+@[A-Za-z0-9.+-]+|go-module\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+@[A-Za-z0-9_-]+)#[a-f0-9]{64}$/u.test(
          location
        ) || !/^[a-f0-9]{64}$/iu.test(digest ?? '')
    ) ||
    [record.baseSha, record.headSha, record.mergeSha].some(
      (sha) => !/^[0-9a-f]{40}$/iu.test(sha ?? '')
    )
  )
    throw new Error(
      'Stage A approval artifact does not match the completed trusted gate run and PR commits'
    );
  return Object.freeze({
    repository: record.repository,
    pullRequest: record.pullRequest,
    baseSha: record.baseSha,
    baseRef: record.baseRef,
    headSha: record.headSha,
    mergeSha: record.mergeSha,
    complexityEvidence: record.complexityEvidence,
    registrySignatureAudit: record.registrySignatureAudit,
    npmProvenanceStatus: record.npmProvenanceStatus,
    npmProvenancePolicySha256: record.npmProvenancePolicySha256,
    npmProvenanceArtifactCount: record.npmProvenanceArtifactCount,
    npmProvenanceVerifiedCount: record.npmProvenanceVerifiedCount,
    verifiedArtifactSha512ByLocation: record.verifiedArtifactSha512ByLocation,
    verifiedArtifactSha256ByLocation: record.verifiedArtifactSha256ByLocation,
    cargoArtifactPolicySha256: record.cargoArtifactPolicySha256,
    coverage: record.coverage,
    exceptionPolicySha256: record.exceptionPolicySha256,
    appliedExceptions: record.appliedExceptions
  });
}

export function verifyCurrentPullRequestIdentity(
  record,
  expectedRepository,
  current
) {
  if (
    !record ||
    record.repository !== expectedRepository ||
    !Number.isSafeInteger(record.pullRequest) ||
    record.baseRef !== 'main' ||
    !/^[0-9a-f]{40}$/iu.test(record.baseSha ?? '') ||
    !/^[0-9a-f]{40}$/iu.test(record.headSha ?? '') ||
    !/^[0-9a-f]{40}$/iu.test(record.mergeSha ?? '')
  )
    throw new Error('Stage A current pull request identity input is invalid');
  if (
    current?.number !== record.pullRequest ||
    current?.state !== 'open' ||
    current?.base?.repo?.full_name !== expectedRepository ||
    current?.base?.ref !== record.baseRef ||
    current?.base?.sha !== record.baseSha ||
    current?.head?.sha !== record.headSha ||
    current?.merge_commit_sha !== record.mergeSha ||
    complexityEvidence(current?.body) !== record.complexityEvidence
  )
    throw new Error('Stage A approval is stale after a pull request update');
  return true;
}

async function main() {
  const artifactPath = process.argv[2];
  const currentPullRequestPath = process.argv[3];
  if (!artifactPath || !currentPullRequestPath)
    throw new Error(
      'Stage A approval and current pull request artifact paths are required'
    );
  const record = JSON.parse(await readFile(artifactPath, 'utf8'));
  const currentPullRequestText = await readFile(currentPullRequestPath, 'utf8');
  if (Buffer.byteLength(currentPullRequestText, 'utf8') > 256 * 1024)
    throw new Error('Stage A current pull request identity exceeds its budget');
  const currentPullRequest = JSON.parse(currentPullRequestText);
  const event = JSON.parse(
    await readFile(process.env.GITHUB_EVENT_PATH, 'utf8')
  );
  const configuredIssuerPolicy =
    process.env.TOOLIP_STAGE_A_NPM_PROVENANCE_POLICY;
  let expectedNpmProvenancePolicySha256;
  if (record?.coverage?.dependencyArtifactCount > 0) {
    if (record.npmProvenanceStatus === 'operator-reviewed') {
      if (configuredIssuerPolicy?.trim())
        throw new Error(
          'Operator review cannot override configured issuer/source policy'
        );
      const policyText = await readFile(
        new URL(
          '../.toolip/stage-a-reviewed-dependencies.json',
          import.meta.url
        ),
        'utf8'
      );
      expectedNpmProvenancePolicySha256 = createHash('sha256')
        .update(policyText, 'utf8')
        .digest('hex');
    } else {
      expectedNpmProvenancePolicySha256 = npmProvenancePolicyDigest(
        configuredIssuerPolicy
      );
    }
  }
  const expectedCargoArtifactPolicySha256 =
    record?.coverage?.cargoDependencyArtifactCount > 0
      ? cargoArtifactPolicyDigest(
          process.env.TOOLIP_STAGE_A_CARGO_SHA256_POLICY
        )
      : undefined;
  const approval = verifyStageAArtifact(
    record,
    event,
    process.env.GITHUB_REPOSITORY,
    { expectedNpmProvenancePolicySha256, expectedCargoArtifactPolicySha256 }
  );
  verifyCurrentPullRequestIdentity(
    record,
    process.env.GITHUB_REPOSITORY,
    currentPullRequest
  );
  await appendFile(
    process.env.GITHUB_OUTPUT,
    `${[
      `repository=${approval.repository}`,
      `pull_request=${approval.pullRequest}`,
      `base_sha=${approval.baseSha}`,
      `base_ref=${approval.baseRef}`,
      `head_sha=${approval.headSha}`,
      `merge_sha=${approval.mergeSha}`,
      `complexity_evidence=${approval.complexityEvidence}`,
      `registry_signature_audit=${approval.registrySignatureAudit}`,
      `npm_provenance_status=${approval.npmProvenanceStatus}`,
      `npm_provenance_policy_sha256=${approval.npmProvenancePolicySha256 ?? 'not-applicable'}`,
      `npm_provenance_artifact_count=${approval.npmProvenanceArtifactCount}`,
      `npm_provenance_verified_count=${approval.npmProvenanceVerifiedCount}`,
      `cargo_artifact_policy_sha256=${approval.cargoArtifactPolicySha256 ?? 'not-applicable'}`,
      `stage_a_exception_count=${approval.appliedExceptions.length}`,
      `stage_a_exception_policy_sha256=${approval.exceptionPolicySha256 ?? 'none'}`
    ].join('\n')}\n`
  );
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  await main();
