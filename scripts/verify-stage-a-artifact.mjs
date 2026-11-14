#!/usr/bin/env node
import { appendFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  cargoArtifactPolicyDigest,
  npmProvenancePolicyDigest
} from './stage-a-canonical-json.mjs';

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
    !(record.coverage?.nonNpmDependencyArtifactCount > 0
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
        entry.reviewedCommit !== record.headSha
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
    record.coverage.dependencyArtifactBinaryFiles !== 0 ||
    record.coverage.nonNpmDependencyArtifactsChecked !==
      record.coverage.nonNpmDependencyArtifactCount ||
    record.coverage.nonNpmDependencyArtifactBinaryFiles !== 0 ||
    record.registrySignatureAudit !==
      (record.coverage.dependencyArtifactCount > 0
        ? 'verified'
        : 'not-applicable') ||
    record.npmProvenanceStatus !==
      (record.coverage.dependencyArtifactCount > 0
        ? 'verified'
        : 'not-applicable') ||
    !(record.coverage.dependencyArtifactCount > 0
      ? /^[0-9a-f]{64}$/iu.test(record.npmProvenancePolicySha256 ?? '')
      : record.npmProvenancePolicySha256 === null) ||
    record.npmProvenanceArtifactCount !==
      record.coverage.dependencyArtifactCount ||
    record.npmProvenanceVerifiedCount !==
      record.coverage.dependencyArtifactCount ||
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
        !/^cargo-lock\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+@[A-Za-z0-9.+-]+#[a-f0-9]{64}$/u.test(
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

export async function verifyCurrentPullRequestIdentity(
  record,
  expectedRepository,
  { token, fetchImpl = globalThis.fetch } = {}
) {
  if (
    !record ||
    record.repository !== expectedRepository ||
    !Number.isSafeInteger(record.pullRequest) ||
    record.baseRef !== 'main' ||
    !/^[0-9a-f]{40}$/iu.test(record.baseSha ?? '') ||
    !/^[0-9a-f]{40}$/iu.test(record.headSha ?? '') ||
    !/^[0-9a-f]{40}$/iu.test(record.mergeSha ?? '') ||
    typeof token !== 'string' ||
    token.length < 20
  )
    throw new Error('Stage A current pull request identity input is invalid');
  const response = await fetchImpl(
    `https://api.github.com/repos/${expectedRepository}/pulls/${record.pullRequest}`,
    {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28'
      }
    }
  );
  if (
    response.status !== 200 ||
    (response.url && new URL(response.url).origin !== 'https://api.github.com')
  )
    throw new Error('Stage A current pull request identity is unavailable');
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > 256 * 1024)
    throw new Error('Stage A current pull request identity exceeds its budget');
  const reader = response.body?.getReader();
  if (!reader)
    throw new Error(
      'Stage A current pull request identity has no response body'
    );
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 256 * 1024) {
        await reader.cancel().catch(() => undefined);
        throw new Error(
          'Stage A current pull request identity exceeds its budget'
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  let current;
  try {
    const payload = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      payload.set(chunk, offset);
      offset += chunk.byteLength;
    }
    current = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(payload)
    );
  } catch {
    throw new Error('Stage A current pull request identity is malformed');
  }
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
  if (!artifactPath)
    throw new Error('Stage A approval artifact path is required');
  const record = JSON.parse(await readFile(artifactPath, 'utf8'));
  const event = JSON.parse(
    await readFile(process.env.GITHUB_EVENT_PATH, 'utf8')
  );
  const expectedNpmProvenancePolicySha256 =
    record?.coverage?.dependencyArtifactCount > 0
      ? npmProvenancePolicyDigest(
          process.env.TOOLIP_STAGE_A_NPM_PROVENANCE_POLICY
        )
      : undefined;
  const expectedCargoArtifactPolicySha256 =
    record?.coverage?.nonNpmDependencyArtifactCount > 0
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
  await verifyCurrentPullRequestIdentity(
    record,
    process.env.GITHUB_REPOSITORY,
    { token: process.env.GITHUB_TOKEN }
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
