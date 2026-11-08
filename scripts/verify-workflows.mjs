#!/usr/bin/env node
/**
 * Static policy gate for .github/workflows/*.yml.
 *
 * Enforces release isolation and least privilege:
 * - release workflows (publish.yml, github-release.yml) are workflow_dispatch only;
 * - nothing else may publish to npm, create releases/tags, or read release secrets;
 * - pull_request_target is restricted to the Stage A data-only scanner;
 * - workflow_run Stage B may install/execute PR code only after a verified gate artifact;
 * - every third-party action pinned to a full commit SHA;
 * - every `npm ci` passes --ignore-scripts;
 * - top-level permissions are declared and read-only; write scopes are job-level
 *   and limited to the allowlist below.
 *
 * Complexity: W workflows, J jobs, S steps in total. Time O(total YAML bytes),
 * space O(largest workflow document). Every check is a single pass.
 */
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import semver from 'semver';
import { parse } from 'yaml';

const DIR = process.env.WORKFLOWS_DIR ?? '.github/workflows';
const RELEASE = new Set(['publish.yml', 'github-release.yml']);
const SHA = /^[0-9a-f]{40}$/u;
const WRITE_ALLOWED = {
  'publish.yml': new Set(['id-token']),
  'github-release.yml': new Set(['contents']),
  'codeql.yml': new Set(['security-events'])
};
const STAGE_B = new Set(['ci.yml', 'pr-quality.yml', 'codeql.yml']);
const problems = [];
const fail = (file, message) => problems.push(`${file}: ${message}`);
let hasStageATrigger = false;

const files = (await readdir(DIR)).filter((f) => /\.ya?ml$/u.test(f)).sort();
for (const file of files) {
  const text = await readFile(path.join(DIR, file), 'utf8');
  const doc = parse(text);
  const triggers = Object.keys(doc.on ?? doc.true ?? {});
  const release = RELEASE.has(file);

  if (triggers.includes('pull_request_target') && file !== 'stage-a.yml')
    fail(file, 'only stage-a.yml may use pull_request_target');
  if (
    release &&
    (triggers.length !== 1 || triggers[0] !== 'workflow_dispatch')
  ) {
    fail(
      file,
      `release workflow must be workflow_dispatch only (found ${triggers.join(', ')})`
    );
  }
  if (!release) {
    if (
      /npm\s+publish|gh\s+release\s+create|NPM_TOKEN|NODE_AUTH_TOKEN|id-token:\s*write/u.test(
        text
      )
    ) {
      fail(
        file,
        'non-release workflow references publish/release credentials or commands'
      );
    }
    if (/secrets\.(?!GITHUB_TOKEN)/u.test(text))
      fail(file, 'non-release workflow reads a secret');
    if (/git\s+(?:push|tag)\b/u.test(text))
      fail(file, 'non-release workflow pushes or tags');
  }

  const top = doc.permissions;
  if (top === undefined || typeof top !== 'object') {
    fail(file, 'top-level permissions must be declared explicitly');
  } else {
    for (const [scope, level] of Object.entries(top)) {
      if (level === 'write') fail(file, `top-level write permission: ${scope}`);
    }
  }
  const allowed = WRITE_ALLOWED[file] ?? new Set();
  if (file === 'stage-a.yml' && triggers.includes('pull_request_target')) {
    hasStageATrigger = true;
    if (!(doc.on?.pull_request_target?.types ?? []).includes('edited'))
      fail(
        file,
        'Stage A must rescan edited pull request metadata so stale approval evidence cannot be reused'
      );
    const scanJob = doc.jobs?.scan;
    const stageASteps = scanJob?.steps ?? [];
    const checkoutSteps = Object.values(doc.jobs ?? {})
      .flatMap((job) => job.steps ?? [])
      .filter((step) => step.uses?.startsWith('actions/checkout@'));
    if (
      Object.keys(doc.jobs ?? {}).join(',') !== 'scan' ||
      checkoutSteps.length !== 1 ||
      !String(checkoutSteps[0]?.with?.ref ?? '').includes(
        'github.event.pull_request.base.sha'
      )
    )
      fail(
        file,
        'Stage A may check out only the trusted base revision; PR blobs must remain Git objects'
      );
    const scannerIndex = stageASteps.findIndex((step) =>
      String(step.run ?? '').includes('scripts/stage-a-gate.mjs')
    );
    const trustedRuntimeIndex = stageASteps.findIndex((step) =>
      step.uses?.startsWith('actions/setup-node@')
    );
    const runtimeVerifierIndex = stageASteps.findIndex((step) =>
      String(step.run ?? '').includes('scripts/verify-node.mjs')
    );
    const writerIndex = stageASteps.findIndex((step) =>
      String(step.run ?? '').includes('scripts/write-stage-a-artifact.mjs')
    );
    const inertInstallIndexes = stageASteps.flatMap((step, index) =>
      typeof step.run === 'string' && /\bnpm\s+ci\b/u.test(step.run)
        ? [index]
        : []
    );
    const approvedInstallIndex = inertInstallIndexes[0] ?? -1;
    const approvalUploadIndex = stageASteps.findIndex(
      (step) =>
        String(step.uses ?? '').startsWith('actions/upload-artifact@') &&
        String(step.with?.name ?? '').startsWith('stage-a-') &&
        !String(step.with?.name ?? '').startsWith('stage-a-diagnostics-')
    );
    const diagnosticUploadIndex = stageASteps.findIndex(
      (step) =>
        String(step.uses ?? '').startsWith('actions/upload-artifact@') &&
        String(step.with?.name ?? '').startsWith('stage-a-diagnostics-')
    );
    const scannerEnv = stageASteps[scannerIndex]?.env ?? {};
    if (
      scannerIndex < 0 ||
      inertInstallIndexes.length !== 1 ||
      trustedRuntimeIndex < 0 ||
      runtimeVerifierIndex <= trustedRuntimeIndex ||
      runtimeVerifierIndex >= scannerIndex ||
      writerIndex <= scannerIndex ||
      (approvedInstallIndex !== -1 &&
        (approvedInstallIndex <= scannerIndex ||
          approvedInstallIndex >= writerIndex ||
          !String(stageASteps[approvedInstallIndex]?.run ?? '').includes(
            'npm ci --ignore-scripts'
          ) ||
          !String(stageASteps[approvedInstallIndex]?.if ?? '').includes(
            "steps.gate.outputs.status == 'approved'"
          ) ||
          !String(
            stageASteps[approvedInstallIndex]?.['working-directory'] ?? ''
          ).includes('toolip-stage-a-dependency-audit') ||
          !String(
            stageASteps[approvedInstallIndex]?.['working-directory'] ?? ''
          ).includes(['$', '{{ runner.temp }}'].join('')) ||
          !String(stageASteps[approvedInstallIndex]?.run ?? '').includes(
            'npm audit signatures --ignore-scripts'
          ) ||
          !String(stageASteps[approvedInstallIndex]?.run ?? '').includes(
            '--registry=https://registry.npmjs.org/'
          ) ||
          stageASteps[approvedInstallIndex]?.env?.npm_config_ignore_scripts !==
            'true')) ||
      approvalUploadIndex <= writerIndex ||
      (diagnosticUploadIndex !== -1 &&
        (diagnosticUploadIndex <= scannerIndex ||
          !String(stageASteps[diagnosticUploadIndex]?.if ?? '').includes(
            'always()'
          ) ||
          !String(
            stageASteps[diagnosticUploadIndex]?.with?.path ?? ''
          ).includes('stage-a-results.sarif'))) ||
      !String(
        stageASteps[scannerIndex]?.env?.TOOLIP_STAGE_A_SHA256 ?? ''
      ).match(/^[0-9a-f]{64}$/u) ||
      stageASteps[writerIndex]?.env?.TOOLIP_STAGE_A_SHA256 !==
        stageASteps[scannerIndex]?.env?.TOOLIP_STAGE_A_SHA256 ||
      scannerEnv.GITHUB_TOKEN === undefined ||
      [
        'STAGE_A_REPOSITORY',
        'STAGE_A_PR_NUMBER',
        'STAGE_A_PR_AUTHOR_ASSOCIATION',
        'STAGE_A_PR_HEAD_REPOSITORY',
        'STAGE_A_PR_HEAD_IS_FORK',
        'STAGE_A_BASE_REPOSITORY',
        'STAGE_A_BASE_SHA',
        'STAGE_A_HEAD_SHA',
        'STAGE_A_MERGE_SHA'
      ].some((name) => typeof scannerEnv[name] !== 'string') ||
      /\$\{\{\s*github\.event\./u.test(
        String(stageASteps[scannerIndex]?.run ?? '')
      ) ||
      stageASteps.some(
        (step, index) =>
          index !== scannerIndex &&
          !inertInstallIndexes.includes(index) &&
          Object.hasOwn(step.env ?? {}, 'GITHUB_TOKEN')
      ) ||
      stageASteps.some(
        (step, index) =>
          typeof step.run === 'string' &&
          !inertInstallIndexes.includes(index) &&
          /\bnpm\s+(?:ci|install|run)|\b(?:npm|pnpm|yarn)\s+exec\b/u.test(
            step.run
          )
      )
    )
      fail(
        file,
        'Stage A must run its digest-pinned self-contained scanner before any PR dependency install, then conditionally install and signature-verify the scanned lock graph before approval'
      );
  }
  if (STAGE_B.has(file) && triggers.includes('workflow_run')) {
    const sources = doc.on?.workflow_run?.workflows ?? [];
    if (!sources.includes('Stage A Trusted Pre-execution Gate'))
      fail(file, 'Stage B must run only after the trusted Stage A workflow');
    if (!(doc.on?.workflow_run?.branches ?? []).includes('main'))
      fail(
        file,
        'Stage B must accept gate runs only for the protected main target'
      );
    const verifier = doc.jobs?.['stage-a-result'];
    const failClosedStep = (verifier?.steps ?? []).find(
      (step) =>
        String(step.if ?? '').includes('workflow_run.conclusion') &&
        String(step.if ?? '').includes("!= 'success'") &&
        String(step.run ?? '').includes('exit 1')
    );
    if (
      !String(verifier?.if ?? '').includes(
        "github.event_name == 'workflow_run'"
      ) ||
      !failClosedStep
    )
      fail(
        file,
        'Stage B must fail visibly when the completed Stage A workflow did not succeed; skipped required jobs can otherwise appear successful'
      );
    if (
      !(verifier?.steps ?? []).some((step) =>
        String(step.run ?? '').includes('verify-stage-a-artifact.mjs')
      )
    )
      fail(file, 'Stage B must validate the exact Stage A run artifact');
    if (
      !triggers.includes('workflow_run') ||
      !(verifier?.steps ?? []).some((step) =>
        String(step.uses ?? '').startsWith('actions/download-artifact@')
      )
    )
      fail(
        file,
        'Stage B must download approval metadata from the triggering Stage A run'
      );
    for (const [jobName, job] of Object.entries(doc.jobs ?? {})) {
      const needs = Array.isArray(job.needs) ? job.needs : [job.needs];
      const executesProject =
        jobName !== 'stage-a-result' &&
        (job.steps ?? []).some(
          (step) =>
            typeof step.run === 'string' ||
            step.uses?.startsWith('actions/checkout@')
        );
      if (executesProject && !needs.includes('stage-a-result'))
        fail(
          file,
          `job ${jobName} may check out or execute project-controlled code without verified Stage A`
        );
      if (jobName !== 'stage-a-result')
        for (const step of job.steps ?? [])
          if (
            step.uses?.startsWith('actions/checkout@') &&
            (step.with?.['persist-credentials'] !== false ||
              !String(step.with?.ref ?? '').includes('merge_sha'))
          )
            fail(
              file,
              `job ${jobName} must check out the verified immutable merge SHA without persisted credentials`
            );
    }
  }
  for (const [jobName, job] of Object.entries(doc.jobs ?? {})) {
    for (const [scope, level] of Object.entries(job.permissions ?? {})) {
      if (level === 'write' && !allowed.has(scope)) {
        fail(
          file,
          `job ${jobName} requests unapproved write permission ${scope}`
        );
      }
    }
    if (!job['timeout-minutes'] && !release && !job.uses)
      fail(file, `job ${jobName} lacks timeout-minutes`);
    for (const step of job.steps ?? []) {
      if (
        typeof step.run === 'string' &&
        /\bnpm\s+ci\b(?![^\n]*--ignore-scripts)/u.test(step.run)
      ) {
        fail(
          file,
          `job ${jobName}: npm ci must use --ignore-scripts so dependency lifecycle scripts never run`
        );
      }
      if (!step.uses || step.uses.startsWith('./')) continue;
      const ref = step.uses.split('@')[1] ?? '';
      if (!SHA.test(ref))
        fail(
          file,
          `job ${jobName}: ${step.uses} is not pinned to a full commit SHA`
        );
    }
  }
}

if (files.includes('stage-a.yml')) {
  const stageAWorkflow = await readFile(path.join(DIR, 'stage-a.yml'), 'utf8');
  const stageA = parse(stageAWorkflow);
  const stageAEvents = Object.keys(stageA.on ?? stageA.true ?? {});
  if (stageAEvents.length !== 1 || stageAEvents[0] !== 'pull_request_target')
    fail(
      'stage-a.yml',
      'trusted Stage A workflow must be the only pull_request_target workflow'
    );
  if (!hasStageATrigger)
    fail('stage-a.yml', 'trusted Stage A pull_request_target event is missing');
  if (stageA.permissions?.contents !== 'read')
    fail(
      'stage-a.yml',
      'trusted scanner workflow must have contents: read only'
    );
  const trustedNodeSetup = stageA.jobs?.scan?.steps?.find((step) =>
    String(step.uses ?? '').startsWith('actions/setup-node@')
  );
  const trustedNodeVersion = String(
    trustedNodeSetup?.with?.['node-version'] ?? ''
  );
  const supportedNodeRange = JSON.parse(await readFile('package.json', 'utf8'))
    .engines?.node;
  if (
    !/^\d+\.\d+\.\d+$/u.test(trustedNodeVersion) ||
    trustedNodeSetup?.with?.['check-latest'] !== false ||
    typeof supportedNodeRange !== 'string' ||
    !semver.satisfies(trustedNodeVersion, supportedNodeRange)
  )
    fail(
      'stage-a.yml',
      'trusted Stage A runtime must use an exact, supported Node.js patch version'
    );
  const scannerDigest = createHash('sha256').update(
    'toolip-stage-a-scanner-v2\0'
  );
  for (const relativePath of [
    'scripts/stage-a-gate.mjs',
    'vendor/stage-a-yaml-parser.mjs'
  ]) {
    const bytes = await readFile(relativePath);
    scannerDigest
      .update(relativePath)
      .update('\0')
      .update(String(bytes.length))
      .update('\0')
      .update(bytes);
  }
  const scannerSha = scannerDigest.digest('hex');
  if (!stageAWorkflow.includes(`TOOLIP_STAGE_A_SHA256: ${scannerSha}`))
    fail(
      'stage-a.yml',
      'trusted scanner digest pin does not match scripts/stage-a-gate.mjs'
    );
  const artifactVerifier = await readFile(
    'scripts/verify-stage-a-artifact.mjs',
    'utf8'
  );
  for (const evidence of [
    'run?.id',
    'run?.conclusion',
    'pull_requests',
    'pr?.base?.sha',
    'pr?.head?.sha',
    "record.status !== 'approved'"
  ])
    if (!artifactVerifier.includes(evidence))
      fail(
        'stage-a.yml',
        `approval verifier is missing required identity check: ${evidence}`
      );
} else if (!process.env.WORKFLOWS_DIR || hasStageATrigger) {
  fail('stage-a.yml', 'trusted Stage A workflow is missing');
}

if (problems.length > 0) {
  console.error(`Workflow policy check failed:\n- ${problems.join('\n- ')}`);
  process.exit(1);
}
console.log(`Workflow policy verified for ${files.length} workflow(s).`);
