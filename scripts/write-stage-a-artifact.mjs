#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { validOwnerAttestationEntry } from './verify-stage-a-artifact.mjs';
import { verifyStageAReviewedDependencyEvidence } from './stage-a-reviewed-baseline.mjs';

const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, 'utf8'));
const pr = event.pull_request;
const repository = process.env.GITHUB_REPOSITORY;
const runId = process.env.GITHUB_RUN_ID;
const runnerTemp = process.env.RUNNER_TEMP;
const scannerSha = process.env.TOOLIP_STAGE_A_SHA256;
if (
  pr?.base?.ref !== 'main' ||
  !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository ?? '') ||
  !/^\d+$/u.test(runId ?? '') ||
  !runnerTemp ||
  !/^[0-9a-f]{64}$/iu.test(scannerSha ?? '')
)
  throw new Error('Stage A event metadata is incomplete');
for (const sha of [pr.base?.sha, pr.head?.sha, pr.merge_commit_sha])
  if (!/^[0-9a-f]{40}$/iu.test(sha ?? ''))
    throw new Error('Stage A event commit identity is unavailable');
const scan = JSON.parse(
  await readFile(path.join(runnerTemp, 'stage-a-scan.json'), 'utf8')
);
if (
  scan?.status !== 'approved' ||
  scan.scannerSha256 !== scannerSha.toLowerCase() ||
  scan.baseCommit !== pr.base.sha ||
  scan.headCommit !== pr.head.sha ||
  scan.mergeCommit !== pr.merge_commit_sha ||
  scan.reasonCodes?.length !== 0 ||
  scan.findings?.length !== 0 ||
  !/^[0-9a-f]{64}$/iu.test(scan.inputSha256 ?? '') ||
  !/^[0-9a-f]{64}$/iu.test(scan.headInputSha256 ?? '') ||
  !Number.isSafeInteger(scan.coverage?.changedFiles) ||
  !Number.isSafeInteger(scan.coverage?.head?.files) ||
  !Number.isSafeInteger(scan.coverage?.head?.textFiles) ||
  !Number.isSafeInteger(scan.coverage?.head?.bytes) ||
  !Number.isSafeInteger(scan.coverage?.merge?.files) ||
  !Number.isSafeInteger(scan.coverage?.merge?.textFiles) ||
  !Number.isSafeInteger(scan.coverage?.merge?.bytes) ||
  !Number.isSafeInteger(scan.coverage?.dependencyArtifactsChecked) ||
  !Number.isSafeInteger(scan.coverage?.dependencyArtifactsChanged) ||
  !Number.isSafeInteger(scan.coverage?.dependencyArtifactCount) ||
  !Number.isSafeInteger(scan.coverage?.dependencyArtifactFiles) ||
  !Number.isSafeInteger(scan.coverage?.dependencyArtifactBytes) ||
  !Number.isSafeInteger(scan.coverage?.dependencyArtifactNetworkBytes) ||
  !Number.isSafeInteger(scan.coverage?.dependencyArtifactBinaryFiles) ||
  !Number.isSafeInteger(scan.coverage?.nonNpmDependencyArtifactsChecked) ||
  !Number.isSafeInteger(scan.coverage?.nonNpmDependencyArtifactCount) ||
  !Number.isSafeInteger(scan.coverage?.cargoDependencyArtifactCount) ||
  !Number.isSafeInteger(scan.coverage?.goDependencyArtifactCount) ||
  !Number.isSafeInteger(scan.coverage?.nonNpmDependencyArtifactFiles) ||
  !Number.isSafeInteger(scan.coverage?.nonNpmDependencyArtifactBytes) ||
  !Number.isSafeInteger(scan.coverage?.nonNpmDependencyArtifactNetworkBytes) ||
  !Number.isSafeInteger(scan.coverage?.nonNpmDependencyArtifactBinaryFiles) ||
  !['verified', 'unverified'].includes(
    scan.coverage?.headCommitSignatureStatus
  ) ||
  scan.coverage.dependencyArtifactsChecked >
    scan.coverage.dependencyArtifactCount ||
  scan.coverage.dependencyArtifactsChanged >
    scan.coverage.dependencyArtifactCount ||
  scan.coverage.dependencyArtifactsChecked !==
    scan.coverage.dependencyArtifactCount ||
  scan.coverage.dependencyArtifactBinaryFiles !==
    scan.coverage.reviewedDependencyBinaryFiles ||
  scan.coverage.nonNpmDependencyArtifactsChecked !==
    scan.coverage.nonNpmDependencyArtifactCount ||
  scan.coverage.cargoDependencyArtifactCount +
    scan.coverage.goDependencyArtifactCount !==
    scan.coverage.nonNpmDependencyArtifactCount ||
  scan.coverage.nonNpmDependencyArtifactBinaryFiles !== 0 ||
  !(scan.coverage.cargoDependencyArtifactCount > 0
    ? /^[0-9a-f]{64}$/iu.test(scan.cargoArtifactPolicySha256 ?? '')
    : scan.cargoArtifactPolicySha256 === null) ||
  !Array.isArray(scan.appliedExceptions) ||
  scan.appliedExceptions.length > 100 ||
  !(
    scan.exceptionPolicySha256 === null ||
    /^[0-9a-f]{64}$/iu.test(scan.exceptionPolicySha256 ?? '')
  ) ||
  scan.appliedExceptions.some(
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
      entry.headInputSha256 !== scan.headInputSha256 ||
      !Number.isFinite(Date.parse(entry.expiresAt)) ||
      typeof entry.reviewer !== 'string' ||
      !entry.reviewer ||
      !Number.isFinite(Date.parse(entry.reviewedAt)) ||
      entry.reviewedCommit !== pr.head.sha
  )
)
  throw new Error('Stage A scan summary does not prove approved full coverage');
const expectedSignatureAudit =
  scan.coverage.dependencyArtifactCount > 0 ? 'verified' : 'not-applicable';
if (process.env.TOOLIP_STAGE_A_SIGNATURE_AUDIT !== expectedSignatureAudit)
  throw new Error(
    'Stage A registry signature audit is missing or inconsistent'
  );
const dependencyArtifactCount = scan.coverage.dependencyArtifactCount;
const verifiedArchiveDigests = scan.verifiedArtifactSha512ByLocation;
const verifiedNonNpmArchiveDigests = scan.verifiedArtifactSha256ByLocation;
if (
  !verifyStageAReviewedDependencyEvidence({
    reviewedReasons: scan.reviewedDependencyReasons,
    reviewedBinaryFiles: scan.reviewedDependencyBinaryFiles,
    baselineSha256: scan.reviewedDependencyBaselineSha256,
    coverage: scan.coverage,
    verifiedArtifactSha512ByLocation: verifiedArchiveDigests
  })
)
  throw new Error(
    'Stage A reviewed dependency evidence is missing or inconsistent'
  );

if (
  !verifiedArchiveDigests ||
  typeof verifiedArchiveDigests !== 'object' ||
  Array.isArray(verifiedArchiveDigests) ||
  Object.keys(verifiedArchiveDigests).length !== dependencyArtifactCount ||
  Object.entries(verifiedArchiveDigests).some(
    ([location, digest]) =>
      !/^node_modules\/(?!.*(?:^|\/)\.\.(?:\/|$))[^\\\0]+$/u.test(location) ||
      !/^[a-f0-9]{128}$/u.test(digest ?? '')
  )
)
  throw new Error('Stage A exact npm archive digest set is incomplete');
if (
  !verifiedNonNpmArchiveDigests ||
  typeof verifiedNonNpmArchiveDigests !== 'object' ||
  Array.isArray(verifiedNonNpmArchiveDigests) ||
  Object.keys(verifiedNonNpmArchiveDigests).length !==
    scan.coverage.nonNpmDependencyArtifactCount ||
  Object.entries(verifiedNonNpmArchiveDigests).some(
    ([location, digest]) =>
      !/^(?:cargo-lock\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+@[A-Za-z0-9.+-]+|go-module\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+@[A-Za-z0-9_-]+)#[a-f0-9]{64}$/u.test(
        location
      ) || !/^[a-f0-9]{64}$/iu.test(digest ?? '')
  )
)
  throw new Error('Stage A exact non-npm archive digest set is incomplete');
if (
  scan.appliedExceptions.some(
    (entry) =>
      !validOwnerAttestationEntry(entry, {
        repository,
        headSha: pr.head.sha,
        headInputSha256: scan.headInputSha256,
        verifiedArtifactSha512ByLocation: verifiedArchiveDigests
      })
  )
)
  throw new Error(
    'Stage A owner attestation does not match the verified archive digest'
  );
let npmProvenanceStatus = 'not-applicable';
let npmProvenancePolicySha256 = null;
let npmProvenanceArtifactCount = 0;
let npmProvenanceVerifiedCount = 0;
let npmOperatorReviewedCount = 0;
if (dependencyArtifactCount > 0) {
  const npmProvenance = JSON.parse(
    await readFile(path.join(runnerTemp, 'stage-a-npm-provenance.json'), 'utf8')
  );
  const isIssuerVerified = npmProvenance?.status === 'verified';
  const isOperatorReviewed = npmProvenance?.status === 'operator-reviewed';
  if (
    npmProvenance?.version !== 1 ||
    !(isIssuerVerified || isOperatorReviewed) ||
    npmProvenance.artifactCount !== dependencyArtifactCount ||
    npmProvenance.failureCount !== 0 ||
    npmProvenance.reasonCodes?.length !== 0 ||
    !/^[0-9a-f]{64}$/iu.test(npmProvenance.policySha256 ?? '') ||
    (isIssuerVerified &&
      (npmProvenance.verifiedCount !== dependencyArtifactCount ||
        (npmProvenance.operatorReviewedCount ?? 0) !== 0)) ||
    (isOperatorReviewed &&
      (npmProvenance.verifiedCount !== 0 ||
        npmProvenance.operatorReviewedCount !== dependencyArtifactCount ||
        npmProvenance.policySha256 !== scan.reviewedDependencyBaselineSha256))
  )
    throw new Error('Stage A npm issuer/source policy result is incomplete');
  npmProvenanceStatus = npmProvenance.status;
  npmProvenancePolicySha256 = npmProvenance.policySha256;
  npmProvenanceArtifactCount = npmProvenance.artifactCount;
  npmProvenanceVerifiedCount = npmProvenance.verifiedCount;
  npmOperatorReviewedCount = npmProvenance.operatorReviewedCount ?? 0;
}
const complexityEvidence = (body) => {
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
};
const record = {
  version: 7,
  repository,
  pullRequest: pr.number,
  runId,
  baseSha: pr.base.sha,
  baseRef: pr.base.ref,
  headSha: pr.head.sha,
  mergeSha: pr.merge_commit_sha,
  scannerSha256: scan.scannerSha256,
  inputSha256: scan.inputSha256,
  headInputSha256: scan.headInputSha256,
  coverage: scan.coverage,
  exceptionPolicySha256: scan.exceptionPolicySha256,
  appliedExceptions: scan.appliedExceptions,
  reviewedDependencyReasons: scan.reviewedDependencyReasons,
  reviewedDependencyBinaryFiles: scan.reviewedDependencyBinaryFiles,
  reviewedDependencyBaselineSha256: scan.reviewedDependencyBaselineSha256,
  registrySignatureAudit: expectedSignatureAudit,
  npmProvenanceStatus,
  npmProvenancePolicySha256,
  npmProvenanceArtifactCount,
  npmProvenanceVerifiedCount,
  npmOperatorReviewedCount,
  verifiedArtifactSha512ByLocation: verifiedArchiveDigests,
  verifiedArtifactSha256ByLocation: verifiedNonNpmArchiveDigests,
  cargoArtifactPolicySha256: scan.cargoArtifactPolicySha256,
  reasonCodes: scan.reasonCodes,
  status: 'approved',
  complexityEvidence: complexityEvidence(pr.body)
};
const target = path.join(runnerTemp, 'stage-a-approval.json');
await writeFile(target, `${JSON.stringify(record)}\n`, {
  flag: 'wx',
  mode: 0o600
});
process.stdout.write(`${target}\n`);
