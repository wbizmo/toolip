#!/usr/bin/env node
/**
 * Applies an operator-owned npm issuer/source policy to the exact archive
 * digests produced by the trusted Stage A scanner. This script runs only from
 * the protected base checkout and never loads project-controlled code.
 */
import { lstat, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readNpmDependencyGraph } from '../dist/src/core/dependencies/inventory.js';
import { verifyStageANpmProvenance } from '../dist/src/core/stage-a-npm-provenance.js';
import { parseNpmProvenancePolicy } from '../dist/src/providers/npm/provenance.js';
import { parseDocument } from '../vendor/stage-a-yaml-parser.mjs';
import { canonicalJsonSha256 } from './stage-a-canonical-json.mjs';

const MAX_SCAN_BYTES = 64 * 1024 * 1024;
const MAX_POLICY_BYTES = 1024 * 1024;

function fail(reason) {
  throw new Error(`stage-a-npm-provenance-${reason}`);
}

async function main() {
  const runnerTemp = process.env.RUNNER_TEMP;
  const dependencyRoot = process.env.TOOLIP_STAGE_A_DEPENDENCY_DIRECTORY;
  const policyText = process.env.TOOLIP_STAGE_A_NPM_PROVENANCE_POLICY;
  const outputPath = path.join(runnerTemp ?? '', 'stage-a-npm-provenance.json');
  if (!runnerTemp || !dependencyRoot || !process.env.GITHUB_OUTPUT)
    fail('inputs-unavailable');
  if (
    typeof policyText !== 'string' ||
    Buffer.byteLength(policyText, 'utf8') === 0 ||
    Buffer.byteLength(policyText, 'utf8') > MAX_POLICY_BYTES
  )
    fail('operator-policy-unavailable');

  const scanPath = path.join(runnerTemp, 'stage-a-scan.json');
  const scanStat = await lstat(scanPath);
  if (
    !scanStat.isFile() ||
    scanStat.isSymbolicLink() ||
    scanStat.size > MAX_SCAN_BYTES
  )
    fail('trusted-scan-result-invalid');
  const scan = JSON.parse(await readFile(scanPath, 'utf8'));
  if (
    scan?.status !== 'approved' ||
    !/^[0-9a-f]{64}$/u.test(scan.scannerSha256 ?? '') ||
    !/^[0-9a-f]{40}$/u.test(scan.headCommit ?? '')
  )
    fail('trusted-scan-result-invalid');

  const policyDocument = parseDocument(policyText, {
    uniqueKeys: true,
    prettyErrors: false
  });
  if (policyDocument.errors.length) fail('operator-policy-invalid');
  let policyValue;
  try {
    policyValue = JSON.parse(policyText);
  } catch {
    fail('operator-policy-invalid');
  }
  const policy = parseNpmProvenancePolicy(policyValue);
  const policySha256 = canonicalJsonSha256(policyValue);

  const digests = scan.verifiedArtifactSha512ByLocation;
  if (
    !digests ||
    typeof digests !== 'object' ||
    Array.isArray(digests) ||
    Object.keys(digests).length !== scan.coverage?.dependencyArtifactCount ||
    Object.entries(digests).some(
      ([location, digest]) =>
        !/^node_modules\/(?!.*(?:^|\/)\.\.(?:\/|$))[^\\\0]+$/u.test(location) ||
        typeof digest !== 'string' ||
        !/^[a-f0-9]{128}$/u.test(digest)
    )
  )
    fail('verified-archive-digests-incomplete');

  const graph = await readNpmDependencyGraph(dependencyRoot);
  if (
    graph.manager !== 'npm' ||
    !graph.complete ||
    graph.warnings.length > 0 ||
    graph.unresolvedDependencies.length > 0 ||
    graph.packages.length !== scan.coverage.dependencyArtifactCount
  )
    fail('lock-graph-incomplete');
  const allowedScopes = (process.env.TOOLIP_STAGE_A_PUBLIC_SCOPES ?? '')
    .split(',')
    .map((scope) => scope.trim())
    .filter(Boolean);
  const verification = await verifyStageANpmProvenance({
    identities: graph.packages,
    verifiedArtifactSha512ByLocation: digests,
    allowedPublicScopes: allowedScopes,
    policy
  });
  if (verification.status !== 'verified') {
    await writeFile(
      outputPath,
      `${JSON.stringify({
        version: 1,
        status: verification.status,
        policySha256,
        artifactCount: verification.artifactCount,
        verifiedCount: verification.verifiedCount,
        failureCount: verification.failureCount,
        reasonCodes: verification.reasonCodes
      })}\n`,
      { flag: 'wx', mode: 0o600 }
    );
    fail('verification-incomplete');
  }

  const result = {
    version: 1,
    status: verification.status,
    policySha256,
    artifactCount: verification.artifactCount,
    verifiedCount: verification.verifiedCount,
    failureCount: verification.failureCount,
    reasonCodes: verification.reasonCodes
  };
  await writeFile(outputPath, `${JSON.stringify(result)}\n`, {
    flag: 'wx',
    mode: 0o600
  });
  process.stdout.write(
    'Stage A npm issuer/source policy verified for every locked artifact.\n'
  );
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main().catch(async (error) => {
    const message = error instanceof Error ? error.message : 'unknown-error';
    const reasonCode = /^stage-a-npm-provenance-[a-z-]+$/u.test(message)
      ? message.replace('stage-a-npm-provenance-', '')
      : 'verification-error';
    if (process.env.RUNNER_TEMP) {
      await writeFile(
        path.join(process.env.RUNNER_TEMP, 'stage-a-npm-provenance.json'),
        `${JSON.stringify({
          version: 1,
          status: 'incomplete',
          policySha256: null,
          artifactCount: 0,
          verifiedCount: 0,
          failureCount: 1,
          reasonCodes: [reasonCode]
        })}\n`,
        { flag: 'wx', mode: 0o600 }
      ).catch(() => undefined);
    }
    process.stderr.write(`${reasonCode}\n`);
    process.exitCode = 1;
  });
