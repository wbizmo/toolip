import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  open,
  lstat,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import semver from 'semver';
import { parseDocument } from 'yaml';
import {
  createProjectSnapshot,
  type ProjectSnapshot
} from '../../application/project-snapshot.js';
import { buildSecurityScorecard } from '../../application/security-scorecard.js';
import type { AnalysisState } from '../../contracts/analysis.js';
import type { Finding } from '../../contracts/finding.js';
import { ToolipError } from '../../errors/toolip-error.js';
import { readNpmDependencyGraph } from '../dependencies/inventory.js';
import {
  evaluatePolicyAsCode,
  loadPolicyAsCode,
  parsePolicyAsCode,
  type PolicyAsCode,
  type PolicyEvaluation
} from '../policy-as-code.js';
import {
  detectPackageManager,
  packageManagerLockfile,
  type PackageManager
} from '../package-manager.js';

const execFileAsync = promisify(execFile);
const dependencySections = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies'
] as const;

type DependencySection = (typeof dependencySections)[number];
type PackageManifest = Record<string, unknown> &
  Partial<Record<DependencySection, Record<string, string>>>;

export type UpgradeVerificationSummary = Readonly<{
  policyDecisionBefore: PolicyEvaluation['decision'];
  policyDecisionAfter: PolicyEvaluation['decision'];
  blockingFindingsBefore: number;
  blockingFindingsAfter: number;
  introducedBlockingFindings: number;
  targetVulnerabilitiesBefore: number;
  targetVulnerabilitiesResolved: number;
  targetVulnerabilitiesRemaining: number;
  baselineCoverage: Readonly<{ eligible: number; scanned: number }>;
  candidateCoverage: Readonly<{ eligible: number; scanned: number }>;
}>;

type CommandResult = {
  stdout: string;
  stderr: string;
};

export type UpgradePrRuntime = {
  exec: (
    command: string,
    args: string[],
    cwd: string,
    signal?: AbortSignal,
    env?: NodeJS.ProcessEnv
  ) => Promise<CommandResult>;
  makeTempDir: (prefix: string) => Promise<string>;
  /** Test seam; production always runs Toolip's shared scorecard. */
  assess?: (
    root: string,
    signal?: AbortSignal,
    allowPublicScope?: boolean
  ) => Promise<UpgradeSecurityAssessment>;
};

export type UpgradeSecurityAssessment = {
  analysis: { state: AnalysisState; reasons: readonly string[] };
  findings: readonly Finding[];
  coverage: { eligible: number; scanned: number };
  projectSnapshot?: ProjectSnapshot;
};

export type UpgradePrOptions = {
  allowProjectTests?: boolean;
  allowPublicScope?: boolean;
  policyFile?: string;
};

const defaultRuntime: UpgradePrRuntime = {
  async exec(command, args, cwd, signal, env) {
    const result = await execFileAsync(command, args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      timeout: 5 * 60 * 1_000,
      killSignal: 'SIGTERM',
      ...(env ? { env } : {}),
      signal
    });

    return {
      stdout: String(result.stdout ?? ''),
      stderr: String(result.stderr ?? '')
    };
  },
  makeTempDir: mkdtemp
};

export async function createUpgradePullRequest(
  root: string,
  packageName: string,
  targetVersion: string,
  dryRun: boolean,
  runtime: UpgradePrRuntime = defaultRuntime,
  signal?: AbortSignal,
  options: UpgradePrOptions = {}
): Promise<{
  branch: string;
  changed: boolean;
  packageManager: Exclude<PackageManager, 'unknown'>;
  verification?: UpgradeVerificationSummary;
}> {
  throwIfAborted(signal);
  let transactionHooksPath: string | undefined;
  let transactionEnvironment: NodeJS.ProcessEnv | undefined;
  let transactionPath: string | undefined;
  const operationRuntime: UpgradePrRuntime = {
    makeTempDir: runtime.makeTempDir,
    exec: (command, args, cwd, childSignal, env) => {
      const commandEnv =
        env ??
        (command === 'git' && transactionPath
          ? { ...process.env, PATH: transactionPath }
          : isPackageManagerCommand(command)
            ? transactionEnvironment
            : undefined);
      return runtime.exec(
        command,
        command === 'git'
          ? [
              '-c',
              'core.fsmonitor=false',
              ...(transactionHooksPath
                ? ['-c', `core.hooksPath=${transactionHooksPath}`]
                : []),
              ...args
            ]
          : args,
        cwd,
        childSignal ?? signal,
        commandEnv
      );
    },
    ...(runtime.assess ? { assess: runtime.assess } : {})
  };
  const absoluteRoot = await realpath(path.resolve(root));
  const normalizedVersion = semver.valid(targetVersion);

  if (!isPackageName(packageName)) {
    throw new ToolipError('A valid npm package name is required.', {
      code: 'UPGRADE_PACKAGE_NAME_INVALID',
      exitCode: 1
    });
  }

  if (!normalizedVersion) {
    throw new ToolipError(
      `Invalid target version: ${targetVersion}. Use an exact semantic version.`,
      {
        code: 'UPGRADE_INVALID_VERSION',
        exitCode: 1
      }
    );
  }

  const repoRoot = await resolveRepositoryRoot(absoluteRoot, operationRuntime);
  const packageRelative = path.relative(repoRoot, absoluteRoot);

  if (packageRelative.startsWith('..') || path.isAbsolute(packageRelative)) {
    throw new ToolipError(
      'Upgrade target must be inside the resolved Git working tree.',
      {
        code: 'UPGRADE_PATH_OUTSIDE_REPOSITORY',
        exitCode: 1
      }
    );
  }

  const manifestPath = path.join(absoluteRoot, 'package.json');
  const manifest = await readManifest(manifestPath);
  const declaredSections = dependencySections.filter(
    (section) => typeof manifest[section]?.[packageName] === 'string'
  );

  if (declaredSections.length === 0) {
    throw new ToolipError(`${packageName} is not declared in package.json.`, {
      code: 'UPGRADE_PACKAGE_NOT_DECLARED',
      exitCode: 1
    });
  }

  const manager = await detectPackageManager(repoRoot);
  if (manager === 'unknown') {
    throw new ToolipError(
      'Unable to determine package manager. A package-lock.json, pnpm-lock.yaml, or yarn.lock file is required.',
      {
        code: 'UPGRADE_PACKAGE_MANAGER_UNKNOWN',
        exitCode: 1
      }
    );
  }
  assertPackageManagerDeclaration(manager, manifest.packageManager);

  const manifestRelative = packageRelative
    ? path.join(packageRelative, 'package.json')
    : 'package.json';
  const packageManifestGitPath = normalizeGitPath(manifestRelative);
  const lockfile = packageManagerLockfile(manager);
  const lockfileGitPath = normalizeGitPath(lockfile);
  const dirtyInputs = await operationRuntime.exec(
    'git',
    [
      'status',
      '--porcelain=v1',
      '--untracked-files=all',
      '--',
      packageManifestGitPath,
      lockfileGitPath
    ],
    repoRoot
  );
  if (dirtyInputs.stdout.trim()) {
    throw new ToolipError(
      'The package manifest or lockfile has uncommitted changes; commit or preserve those changes before proposing an upgrade.',
      { code: 'UPGRADE_INPUTS_DIRTY', exitCode: 1 }
    );
  }

  await requireOrigin(repoRoot, operationRuntime);

  const branchBase = `toolip/upgrade-${sanitizeBranchPart(packageName)}-${sanitizeBranchPart(normalizedVersion)}`;
  const branch = await chooseAvailableBranch(
    repoRoot,
    branchBase,
    operationRuntime
  );

  if (dryRun) {
    return {
      branch,
      changed: true,
      packageManager: manager
    };
  }

  if (options.allowProjectTests !== true) {
    throw new ToolipError(
      'Running project-defined tests requires explicit --allow-project-tests authorization.',
      {
        code: 'UPGRADE_PROJECT_TESTS_NOT_APPROVED',
        exitCode: 1
      }
    );
  }

  const tempRoot = await operationRuntime.makeTempDir(
    path.join(os.tmpdir(), 'toolip-upgrade-pr-')
  );
  transactionHooksPath = path.join(tempRoot, 'disabled-git-hooks');
  const worktree = path.join(tempRoot, 'worktree');
  const worktreeManifest = path.join(worktree, manifestRelative);
  let pushAttempted = false;
  let prCreationAttempted = false;
  let prCreated = false;
  let verification: UpgradeVerificationSummary | undefined;

  try {
    await mkdir(transactionHooksPath, { mode: 0o700 });
    const projectEnvironment = await createIsolatedProjectEnvironment(
      tempRoot,
      repoRoot
    );
    transactionEnvironment = projectEnvironment;
    transactionPath = projectEnvironment.PATH;
    throwIfAborted(signal);
    await operationRuntime.exec(
      'git',
      ['worktree', 'add', '-b', branch, worktree, 'HEAD'],
      repoRoot
    );
    throwIfAborted(signal);
    await assertSafePackageManagerConfiguration(worktree, manager);

    // Prove the before-state from its immutable lock graph, too. Both installs
    // suppress lifecycle hooks; only the explicitly approved test command can
    // execute project-controlled code.
    await installFrozenDependencies(
      manager,
      worktree,
      operationRuntime,
      projectEnvironment
    );
    throwIfAborted(signal);
    const baseline = await assessUpgradeProject(
      worktree,
      operationRuntime,
      signal,
      options.allowPublicScope
    );
    assertAssessmentComplete(baseline, 'baseline');

    for (const section of declaredSections) {
      const dependencies = manifest[section];
      if (dependencies) dependencies[packageName] = normalizedVersion;
    }

    await writeFile(
      worktreeManifest,
      `${JSON.stringify(manifest, null, 2)}\n`,
      'utf8'
    );

    await updateLockfile(
      manager,
      worktree,
      operationRuntime,
      projectEnvironment
    );
    throwIfAborted(signal);
    await installFrozenDependencies(
      manager,
      worktree,
      operationRuntime,
      projectEnvironment
    );
    throwIfAborted(signal);
    await assertResolvedUpgradeTarget(worktree, packageName, normalizedVersion);
    const verifiedInputs = await hashUpgradeInputs(
      worktree,
      packageManifestGitPath,
      lockfileGitPath
    );
    await runTests(manager, worktree, operationRuntime, projectEnvironment);
    throwIfAborted(signal);
    await assertUpgradeInputsUnchanged(
      worktree,
      packageManifestGitPath,
      lockfileGitPath,
      verifiedInputs
    );
    await assertResolvedUpgradeTarget(worktree, packageName, normalizedVersion);

    const candidate = await assessUpgradeProject(
      worktree,
      operationRuntime,
      signal,
      options.allowPublicScope
    );
    assertAssessmentComplete(candidate, 'candidate');
    const verificationPolicy = await readUpgradePolicy(
      worktree,
      options.policyFile,
      candidate.projectSnapshot
    );
    verification = compareUpgradeAssessments({
      packageName,
      targetVersion: normalizedVersion,
      policy: verificationPolicy,
      baseline,
      candidate
    });
    await assertOnlyExpectedUpgradeFilesChanged(
      worktree,
      packageManifestGitPath,
      lockfileGitPath,
      operationRuntime
    );
    await operationRuntime.exec('git', ['diff', '--check'], worktree);

    await operationRuntime.exec(
      'git',
      ['add', packageManifestGitPath, lockfileGitPath],
      worktree
    );
    await operationRuntime.exec(
      'git',
      ['commit', '-m', `chore: upgrade ${packageName} to ${normalizedVersion}`],
      worktree
    );
    throwIfAborted(signal);
    pushAttempted = true;
    await operationRuntime.exec(
      'git',
      ['push', '-u', 'origin', branch],
      worktree
    );

    prCreationAttempted = true;
    await operationRuntime.exec(
      'gh',
      [
        'pr',
        'create',
        '--head',
        branch,
        '--title',
        `chore: upgrade ${packageName} to ${normalizedVersion}`,
        '--body',
        renderUpgradePullRequestBody(verification)
      ],
      worktree
    );
    prCreated = true;

    return {
      branch,
      changed: true,
      packageManager: manager,
      verification
    };
  } finally {
    await bestEffort(() =>
      runtime.exec('git', ['worktree', 'remove', '--force', worktree], repoRoot)
    );
    await bestEffort(() => rm(tempRoot, { recursive: true, force: true }));
    await bestEffort(() =>
      runtime.exec('git', ['branch', '-D', branch], repoRoot)
    );

    if (
      pushAttempted &&
      !prCreated &&
      (!prCreationAttempted ||
        (await remotePullRequestExists(branch, repoRoot, operationRuntime)) ===
          false)
    ) {
      await bestEffort(() =>
        runtime.exec('git', ['push', 'origin', '--delete', branch], repoRoot)
      );
    }
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new ToolipError('Upgrade PR operation was cancelled.', {
      code: 'UPGRADE_CANCELLED',
      exitCode: 1
    });
  }
}

function isPackageName(value: string): boolean {
  return (
    value.length <= 214 &&
    /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u.test(value)
  );
}

function isPackageManagerCommand(command: string): boolean {
  return command === 'npm' || command === 'pnpm' || command === 'yarn';
}

async function assessUpgradeProject(
  root: string,
  runtime: UpgradePrRuntime,
  signal: AbortSignal | undefined,
  allowPublicScope: boolean | undefined
): Promise<UpgradeSecurityAssessment> {
  if (runtime.assess) return runtime.assess(root, signal, allowPublicScope);
  const projectSnapshot = await createProjectSnapshot(root, { signal });
  const scorecard = await buildSecurityScorecard(
    root,
    {},
    {
      projectSnapshot,
      budget: { totalMs: 180_000, signal },
      allowPublicScope: allowPublicScope === true,
      offline: false
    }
  );
  return {
    analysis: scorecard.analysis,
    findings: scorecard.findings,
    coverage: scorecard.coverage,
    projectSnapshot
  };
}

function assertAssessmentComplete(
  assessment: UpgradeSecurityAssessment,
  phase: 'baseline' | 'candidate'
): void {
  if (assessment.analysis.state !== 'complete') {
    throw new ToolipError(
      `The ${phase} security assessment was incomplete; no upgrade pull request will be created.`,
      { code: 'UPGRADE_SECURITY_ASSESSMENT_INCOMPLETE', exitCode: 1 }
    );
  }
}

async function assertResolvedUpgradeTarget(
  worktree: string,
  packageName: string,
  version: string
): Promise<void> {
  const graph = await readNpmDependencyGraph(worktree);
  if (!graph.complete) {
    throw new ToolipError(
      'The updated lockfile does not resolve to a complete, exact dependency graph.',
      { code: 'UPGRADE_LOCK_GRAPH_INCOMPLETE', exitCode: 1 }
    );
  }
  const exactDirectTarget = graph.packages.some(
    (item) =>
      item.name === packageName &&
      item.version === version &&
      item.direct &&
      item.resolutionConfidence === 'lockfile'
  );
  if (!exactDirectTarget) {
    throw new ToolipError(
      'The lockfile does not contain the requested package version as an exact direct dependency.',
      { code: 'UPGRADE_TARGET_NOT_RESOLVED', exitCode: 1 }
    );
  }
}

async function readUpgradePolicy(
  root: string,
  configuredPath?: string,
  snapshot?: ProjectSnapshot
): Promise<PolicyAsCode> {
  const defaultPolicy = parsePolicyAsCode(
    JSON.stringify({
      version: 1,
      minimumSeverity: 'high',
      minimumCoverage: 1,
      blockKnownExploited: true,
      ruleSets: ['all'],
      rules: {},
      suppressions: []
    })
  ).policy;
  const policyPath = path.resolve(
    root,
    configuredPath ?? '.toolip/policy.yaml'
  );
  const relativePath = path.relative(root, policyPath);
  const insideRoot =
    !path.isAbsolute(relativePath) &&
    relativePath !== '..' &&
    !relativePath.startsWith(`..${path.sep}`);
  if (snapshot && insideRoot) {
    const normalizedPath = relativePath.split(path.sep).join('/');
    const captured = snapshot.files.find(
      (file) => file.path === normalizedPath
    );
    if (captured?.content !== undefined)
      return tightenUpgradePolicy(parsePolicyAsCode(captured.content).policy);
    try {
      await lstat(policyPath);
    } catch (error) {
      if (isMissingFile(error)) return defaultPolicy;
      throw new ToolipError(
        'The configured upgrade policy could not be inspected safely.',
        { code: 'UPGRADE_POLICY_INVALID', exitCode: 1 }
      );
    }
    throw new ToolipError(
      'The configured upgrade policy was not captured as bounded project input.',
      { code: 'UPGRADE_POLICY_SNAPSHOT_UNAVAILABLE', exitCode: 1 }
    );
  }
  let parsed: PolicyAsCode;
  try {
    parsed = (await loadPolicyAsCode(policyPath)).policy;
  } catch (error) {
    if (isMissingFile(error)) return defaultPolicy;
    throw new ToolipError(
      'The configured upgrade policy is invalid or cannot be read safely.',
      { code: 'UPGRADE_POLICY_INVALID', exitCode: 1 }
    );
  }
  return tightenUpgradePolicy(parsed);
}

function tightenUpgradePolicy(parsed: PolicyAsCode): PolicyAsCode {
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const configured = parsed.minimumSeverity;
  const effectiveSeverity = configured
    ? severityOrder[
        Math.min(
          severityOrder.indexOf(configured),
          severityOrder.indexOf('high')
        )
      ]
    : 'high';
  // A repository policy may make the gate stricter. It cannot disable rules,
  // lower the minimum measured coverage, choose a partial rule set or suppress
  // findings because it comes from the repository being scanned.
  return {
    ...parsed,
    minimumSeverity: effectiveSeverity,
    minimumCoverage: 1,
    blockKnownExploited: true,
    ruleSets: ['all']
  };
}

function compareUpgradeAssessments(input: {
  packageName: string;
  targetVersion: string;
  policy: PolicyAsCode;
  baseline: UpgradeSecurityAssessment;
  candidate: UpgradeSecurityAssessment;
}): UpgradeVerificationSummary {
  const trust = { trusted: false, source: 'repository' as const };
  const before = evaluatePolicyAsCode({
    policy: input.policy,
    trust,
    findings: input.baseline.findings,
    analysisState: input.baseline.analysis.state,
    coverage: input.baseline.coverage
  });
  const after = evaluatePolicyAsCode({
    policy: input.policy,
    trust,
    findings: input.candidate.findings,
    analysisState: input.candidate.analysis.state,
    coverage: input.candidate.coverage
  });
  if (
    before.decision === 'misconfigured' ||
    before.decision === 'incomplete' ||
    after.decision === 'misconfigured' ||
    after.decision === 'incomplete'
  ) {
    throw new ToolipError(
      'The upgrade policy could not produce a complete decision.',
      { code: 'UPGRADE_POLICY_INCOMPLETE', exitCode: 1 }
    );
  }

  const beforeKeys = new Set(before.findings.map(policyFindingKey));
  const introduced = after.findings.filter(
    (finding) => !beforeKeys.has(policyFindingKey(finding))
  );
  if (introduced.length > 0) {
    throw new ToolipError(
      `The upgrade introduces ${introduced.length} new policy-blocking finding(s); no pull request will be created.`,
      { code: 'UPGRADE_POLICY_REGRESSION', exitCode: 1 }
    );
  }

  const targetBefore = input.baseline.findings.filter(
    (finding) =>
      finding.category === 'vulnerability' &&
      finding.metadata?.package === input.packageName
  );
  const targetAfter = input.candidate.findings.filter(
    (finding) =>
      finding.category === 'vulnerability' &&
      finding.metadata?.package === input.packageName
  );
  for (const finding of targetBefore) {
    const remediationPath = finding.metadata?.remediationPath;
    const rawFixedVersions =
      remediationPath && typeof remediationPath === 'object'
        ? (remediationPath as { fixedVersions?: unknown }).fixedVersions
        : undefined;
    const fixedVersions = new Set<string>(
      Array.isArray(rawFixedVersions)
        ? rawFixedVersions.filter(
            (version): version is string => typeof version === 'string'
          )
        : []
    );
    if (finding.remediation?.fixedVersion)
      fixedVersions.add(finding.remediation.fixedVersion);
    const verifiedFixed = [...fixedVersions].some((version) => {
      const fixed = semver.valid(version);
      return fixed !== null && semver.gte(input.targetVersion, fixed);
    });
    if (!verifiedFixed) {
      throw new ToolipError(
        'The requested target version is not a verified fix for every current advisory affecting the package.',
        { code: 'UPGRADE_TARGET_NOT_VERIFIED_FIX', exitCode: 1 }
      );
    }
  }
  const resolvedVulnerabilityIds = new Set(
    targetAfter.map((finding) =>
      String(finding.metadata?.vulnerabilityId ?? finding.id)
    )
  );
  const remaining = targetBefore.filter((finding) =>
    resolvedVulnerabilityIds.has(
      String(finding.metadata?.vulnerabilityId ?? finding.id)
    )
  );
  if (remaining.length > 0) {
    throw new ToolipError(
      `The candidate remains affected by ${remaining.length} advisory finding(s) for ${input.packageName}; no pull request will be created.`,
      { code: 'UPGRADE_REMEDIATION_UNVERIFIED', exitCode: 1 }
    );
  }

  return Object.freeze({
    policyDecisionBefore: before.decision,
    policyDecisionAfter: after.decision,
    blockingFindingsBefore: before.findings.length,
    blockingFindingsAfter: after.findings.length,
    introducedBlockingFindings: introduced.length,
    targetVulnerabilitiesBefore: targetBefore.length,
    targetVulnerabilitiesResolved: targetBefore.length - remaining.length,
    targetVulnerabilitiesRemaining: remaining.length,
    baselineCoverage: Object.freeze({ ...input.baseline.coverage }),
    candidateCoverage: Object.freeze({ ...input.candidate.coverage })
  });
}

function policyFindingKey(finding: Finding): string {
  return `${finding.id}\0${finding.ruleId}\0${finding.severity}`;
}

function renderUpgradePullRequestBody(
  summary: UpgradeVerificationSummary
): string {
  const unresolved = Math.max(
    0,
    summary.blockingFindingsAfter - summary.introducedBlockingFindings
  );
  return [
    '## Verified dependency upgrade',
    '',
    '- Toolip resolved the updated lockfile to an exact direct package instance.',
    '- Frozen dependency installation completed with lifecycle scripts disabled.',
    '- The explicitly authorized project test command passed.',
    '- Complete baseline and candidate Toolip security assessments passed.',
    `- Policy decision: ${summary.policyDecisionBefore} before, ${summary.policyDecisionAfter} after.`,
    `- Blocking findings: ${summary.blockingFindingsBefore} before, ${summary.blockingFindingsAfter} after; ${summary.introducedBlockingFindings} introduced.`,
    `- Target-package advisories: ${summary.targetVulnerabilitiesResolved} resolved, ${summary.targetVulnerabilitiesRemaining} remaining.`,
    `- Remaining policy findings after the upgrade: ${unresolved}.`,
    `- Coverage: baseline ${summary.baselineCoverage.scanned}/${summary.baselineCoverage.eligible}; candidate ${summary.candidateCoverage.scanned}/${summary.candidateCoverage.eligible}.`,
    '',
    '## Review and rollback',
    '',
    'Human review is required; this PR is never auto-merged. To roll back, close the PR and revert only its package manifest and lockfile changes. No project lifecycle scripts were run during either dependency install.',
    '',
    'Toolip includes identifiers and counts only. It does not copy source excerpts, secrets or provider response bodies into this description.'
  ].join('\n');
}

async function assertOnlyExpectedUpgradeFilesChanged(
  worktree: string,
  manifestPath: string,
  lockfilePath: string,
  runtime: UpgradePrRuntime
): Promise<void> {
  const [tracked, untracked] = await Promise.all([
    runtime.exec('git', ['diff', '--name-only', '-z', 'HEAD'], worktree),
    runtime.exec(
      'git',
      ['ls-files', '--others', '--exclude-standard', '-z'],
      worktree
    )
  ]);
  const allowed = new Set([manifestPath, lockfilePath]);
  const changed = [
    ...tracked.stdout.split('\0'),
    ...untracked.stdout.split('\0')
  ].filter(Boolean);
  const unexpected = changed.filter((file) => !allowed.has(file));
  if (unexpected.length > 0 || changed.length === 0) {
    throw new ToolipError(
      'The isolated upgrade worktree contains unexpected changes; no pull request will be created.',
      { code: 'UPGRADE_DIFF_UNEXPECTED', exitCode: 1 }
    );
  }
}

async function hashUpgradeInputs(
  root: string,
  manifestPath: string,
  lockfilePath: string
): Promise<ReadonlyMap<string, string>> {
  const inputs = new Map<string, string>();
  for (const relativePath of [manifestPath, lockfilePath]) {
    const bytes = await readBoundedRegularFile(
      path.join(root, relativePath),
      root,
      relativePath === manifestPath ? 1_048_576 : 64 * 1024 * 1024
    );
    inputs.set(relativePath, createHash('sha256').update(bytes).digest('hex'));
  }
  return inputs;
}

async function assertUpgradeInputsUnchanged(
  root: string,
  manifestPath: string,
  lockfilePath: string,
  expected: ReadonlyMap<string, string>
): Promise<void> {
  const actual = await hashUpgradeInputs(root, manifestPath, lockfilePath);
  if (
    [...expected].some(
      ([relativePath, digest]) => actual.get(relativePath) !== digest
    )
  ) {
    throw new ToolipError(
      'The project test command changed the verified package manifest or lockfile; no pull request will be created.',
      { code: 'UPGRADE_INPUTS_CHANGED_DURING_TEST', exitCode: 1 }
    );
  }
}

function isMissingFile(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  return 'code' in error && error.code === 'ENOENT';
}

async function resolveRepositoryRoot(
  root: string,
  runtime: UpgradePrRuntime
): Promise<string> {
  try {
    const result = await runtime.exec(
      'git',
      ['rev-parse', '--show-toplevel'],
      root
    );
    return await realpath(path.resolve(result.stdout.trim()));
  } catch {
    throw new ToolipError('Upgrade PR creation requires a Git working tree.', {
      code: 'UPGRADE_GIT_REQUIRED',
      exitCode: 1
    });
  }
}

async function readManifest(manifestPath: string): Promise<PackageManifest> {
  try {
    const root = path.dirname(manifestPath);
    const bytes = await readBoundedRegularFile(manifestPath, root, 1_048_576);
    return JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    ) as PackageManifest;
  } catch {
    throw new ToolipError(
      'Unable to read a valid package.json for the upgrade target.',
      {
        code: 'UPGRADE_MANIFEST_INVALID',
        exitCode: 1
      }
    );
  }
}

/** Reads a bounded regular file under a canonical root without following links. */
async function readBoundedRegularFile(
  filePath: string,
  root: string,
  maximumBytes: number
): Promise<Buffer> {
  const canonicalRoot = await realpath(root);
  const absolute = path.resolve(filePath);
  const before = await lstat(absolute, { bigint: true });
  const inside = (candidate: string): boolean => {
    const relative = path.relative(canonicalRoot, candidate);
    return (
      !path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`)
    );
  };
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size > BigInt(maximumBytes) ||
    !inside(await realpath(absolute))
  )
    throw new Error('project input is not a bounded regular file in the root');
  const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
  const nonBlocking = process.platform === 'win32' ? 0 : constants.O_NONBLOCK;
  const handle = await open(
    absolute,
    constants.O_RDONLY | noFollow | nonBlocking
  );
  try {
    const opened = await handle.stat({ bigint: true });
    const named = await lstat(absolute, { bigint: true });
    if (
      !opened.isFile() ||
      named.isSymbolicLink() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.dev !== named.dev ||
      opened.ino !== named.ino ||
      opened.size !== before.size ||
      opened.size > BigInt(maximumBytes)
    )
      throw new Error('project input changed while opening');
    const bytes = Buffer.alloc(Number(opened.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await handle.read(
        bytes,
        length,
        bytes.length - length,
        null
      );
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(absolute, { bigint: true });
    if (
      length > maximumBytes ||
      BigInt(length) !== opened.size ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      afterPath.isSymbolicLink() ||
      afterPath.dev !== opened.dev ||
      afterPath.ino !== opened.ino ||
      !inside(await realpath(absolute))
    )
      throw new Error('project input changed while reading');
    return bytes.subarray(0, length);
  } finally {
    await handle.close();
  }
}

async function requireOrigin(
  repoRoot: string,
  runtime: UpgradePrRuntime
): Promise<void> {
  try {
    await runtime.exec('git', ['remote', 'get-url', 'origin'], repoRoot);
  } catch {
    throw new ToolipError(
      'Upgrade PR creation requires an origin Git remote.',
      {
        code: 'UPGRADE_ORIGIN_REQUIRED',
        exitCode: 1
      }
    );
  }
}

async function chooseAvailableBranch(
  repoRoot: string,
  base: string,
  runtime: UpgradePrRuntime
): Promise<string> {
  for (let suffix = 1; suffix <= 50; suffix += 1) {
    const candidate = suffix === 1 ? base : `${base}-${suffix}`;
    const local = await localBranchExists(repoRoot, candidate, runtime);
    const remote = await remoteBranchExists(repoRoot, candidate, runtime);

    if (!local && !remote) return candidate;
  }

  throw new ToolipError('Unable to allocate a unique upgrade branch name.', {
    code: 'UPGRADE_BRANCH_COLLISION',
    exitCode: 1
  });
}

async function localBranchExists(
  repoRoot: string,
  branch: string,
  runtime: UpgradePrRuntime
): Promise<boolean> {
  try {
    await runtime.exec(
      'git',
      ['show-ref', '--verify', '--quiet', `refs/heads/${branch}`],
      repoRoot
    );
    return true;
  } catch {
    return false;
  }
}

async function remoteBranchExists(
  repoRoot: string,
  branch: string,
  runtime: UpgradePrRuntime
): Promise<boolean> {
  const result = await runtime.exec(
    'git',
    ['ls-remote', '--heads', 'origin', `refs/heads/${branch}`],
    repoRoot
  );
  return result.stdout.trim().length > 0;
}

/**
 * Returns undefined when GitHub cannot prove whether PR creation succeeded.
 * In that ambiguous case the remote branch is retained to avoid breaking a PR
 * that the CLI may have created before its request timed out.
 */
async function remotePullRequestExists(
  branch: string,
  repoRoot: string,
  runtime: UpgradePrRuntime
): Promise<boolean | undefined> {
  try {
    const result = await runtime.exec(
      'gh',
      ['pr', 'list', '--state', 'all', '--head', branch, '--json', 'number'],
      repoRoot
    );
    const parsed: unknown = JSON.parse(result.stdout);
    if (
      !Array.isArray(parsed) ||
      parsed.some(
        (item) =>
          !item ||
          typeof item !== 'object' ||
          !('number' in item) ||
          !Number.isSafeInteger(item.number) ||
          item.number < 1
      )
    )
      return undefined;
    return parsed.length > 0;
  } catch {
    return undefined;
  }
}

async function updateLockfile(
  manager: Exclude<PackageManager, 'unknown'>,
  cwd: string,
  runtime: UpgradePrRuntime,
  env: NodeJS.ProcessEnv
): Promise<void> {
  if (manager === 'npm') {
    await runtime.exec(
      'npm',
      ['install', '--package-lock-only', '--ignore-scripts'],
      cwd,
      undefined,
      env
    );
    return;
  }

  if (manager === 'pnpm') {
    await runtime.exec(
      'pnpm',
      ['install', '--lockfile-only', '--ignore-scripts'],
      cwd,
      undefined,
      env
    );
    return;
  }

  const version = await supportedManagerVersion('yarn', cwd, runtime, env);
  const major = semver.major(version);

  if (Number.isInteger(major) && major >= 2) {
    await runtime.exec(
      'yarn',
      ['install', '--mode=update-lockfile'],
      cwd,
      undefined,
      env
    );
    return;
  }

  await runtime.exec(
    'yarn',
    ['install', '--ignore-scripts', '--non-interactive'],
    cwd,
    undefined,
    env
  );
}

async function runTests(
  manager: Exclude<PackageManager, 'unknown'>,
  cwd: string,
  runtime: UpgradePrRuntime,
  env: NodeJS.ProcessEnv
): Promise<void> {
  await runtime.exec(manager, ['test'], cwd, undefined, env);
}

/** Install exactly the just-written lock graph without invoking dependency hooks. */
/** @internal Install a lockfile exactly as verified without lifecycle hooks. */
export async function installFrozenDependencies(
  manager: Exclude<PackageManager, 'unknown'>,
  cwd: string,
  runtime: UpgradePrRuntime,
  env?: NodeJS.ProcessEnv
): Promise<void> {
  const version = await supportedManagerVersion(manager, cwd, runtime, env);
  if (manager === 'npm') {
    await runtime.exec('npm', ['ci', '--ignore-scripts'], cwd, undefined, env);
    return;
  }

  if (manager === 'pnpm') {
    await runtime.exec(
      'pnpm',
      ['install', '--frozen-lockfile', '--ignore-scripts'],
      cwd,
      undefined,
      env
    );
    return;
  }

  const major = semver.major(version);
  if (Number.isInteger(major) && major >= 2) {
    await runtime.exec(
      'yarn',
      ['install', '--immutable', '--mode=skip-build'],
      cwd,
      undefined,
      env
    );
    return;
  }

  await runtime.exec(
    'yarn',
    ['install', '--frozen-lockfile', '--ignore-scripts', '--non-interactive'],
    cwd,
    undefined,
    env
  );
}

function assertPackageManagerDeclaration(
  detected: Exclude<PackageManager, 'unknown'>,
  declaration: unknown
): void {
  if (declaration === undefined) return;
  if (typeof declaration !== 'string') {
    throw new ToolipError(
      'packageManager must be an exact supported manager pin.',
      {
        code: 'UPGRADE_PACKAGE_MANAGER_VERSION_UNSUPPORTED',
        exitCode: 1
      }
    );
  }
  const separator = declaration.indexOf('@');
  const declaredManager = declaration.slice(0, separator);
  const declaredVersion = declaration.slice(separator + 1).split('+sha', 1)[0];
  if (
    separator < 1 ||
    declaredManager !== detected ||
    !declaredVersion ||
    !semver.valid(declaredVersion) ||
    !isSupportedManagerVersion(detected, declaredVersion)
  ) {
    throw new ToolipError(
      'packageManager does not select an exact supported version matching the detected lockfile.',
      {
        code: 'UPGRADE_PACKAGE_MANAGER_VERSION_UNSUPPORTED',
        exitCode: 1
      }
    );
  }
}

async function supportedManagerVersion(
  manager: Exclude<PackageManager, 'unknown'>,
  cwd: string,
  runtime: UpgradePrRuntime,
  env?: NodeJS.ProcessEnv
): Promise<string> {
  const result = await runtime.exec(
    manager,
    ['--version'],
    cwd,
    undefined,
    env
  );
  const version = result.stdout.trim().split(/\s+/u, 1)[0] ?? '';
  const valid = semver.valid(version);
  if (!valid || !isSupportedManagerVersion(manager, valid)) {
    throw new ToolipError(
      `Unsupported ${manager} version${version ? ` ${version}` : ''}; frozen upgrade verification requires a recognized lockfile-compatible release.`,
      {
        code: 'UPGRADE_PACKAGE_MANAGER_VERSION_UNSUPPORTED',
        exitCode: 1
      }
    );
  }
  return valid;
}

function isSupportedManagerVersion(
  manager: Exclude<PackageManager, 'unknown'>,
  version: string
): boolean {
  switch (manager) {
    case 'npm':
      return semver.satisfies(version, '>=7 <12');
    case 'pnpm':
      return semver.satisfies(version, '>=6 <13');
    case 'yarn':
      return (
        semver.satisfies(version, '>=1.22.0 <2') ||
        semver.satisfies(version, '>=2 <5')
      );
  }
}

async function createIsolatedProjectEnvironment(
  tempRoot: string,
  repoRoot: string
): Promise<NodeJS.ProcessEnv> {
  const privateHome = path.join(tempRoot, 'home');
  const privateConfig = path.join(tempRoot, 'config');
  const npmConfig = path.join(privateConfig, 'npmrc');
  const gitConfig = path.join(privateConfig, 'gitconfig');
  await mkdir(privateHome, { recursive: true, mode: 0o700 });
  await mkdir(privateConfig, { recursive: true, mode: 0o700 });
  await writeFile(
    npmConfig,
    `${[
      'registry=https://registry.npmjs.org/',
      'ignore-scripts=true',
      'audit=false',
      'fund=false',
      'strict-ssl=true',
      `cache=${path.join(tempRoot, 'npm-cache')}`
    ].join('\n')}\n`,
    { mode: 0o600 }
  );
  await writeFile(gitConfig, '', { mode: 0o600 });

  const safePathEntries: string[] = [];
  for (const entry of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!entry || !path.isAbsolute(entry)) continue;
    const absolute = path.resolve(entry);
    if (
      isWithinDirectory(repoRoot, absolute) ||
      isWithinDirectory(tempRoot, absolute)
    )
      continue;
    const canonical = await realpath(absolute).catch(() => undefined);
    if (!canonical) continue;
    if (
      isWithinDirectory(repoRoot, canonical) ||
      isWithinDirectory(tempRoot, canonical)
    )
      continue;
    const metadata = await stat(canonical).catch(() => undefined);
    if (!metadata?.isDirectory()) continue;
    if (process.platform !== 'win32' && (metadata.mode & 0o022) !== 0) continue;
    safePathEntries.push(absolute);
  }
  if (safePathEntries.length === 0) {
    throw new ToolipError(
      'No trusted package-manager executable path remains after isolating the project environment.',
      { code: 'UPGRADE_PACKAGE_MANAGER_PATH_UNAVAILABLE', exitCode: 1 }
    );
  }

  const env: NodeJS.ProcessEnv = {
    PATH: safePathEntries.join(path.delimiter),
    HOME: privateHome,
    USERPROFILE: privateHome,
    CI: '1',
    NPM_CONFIG_USERCONFIG: npmConfig,
    NPM_CONFIG_GLOBALCONFIG: gitConfig,
    NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org/',
    NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_FUND: 'false',
    COREPACK_ENABLE_PROJECT_SPEC: '0',
    COREPACK_ENABLE_NETWORK: '0',
    YARN_IGNORE_PATH: '1',
    YARN_ENABLE_SCRIPTS: '0',
    GIT_CONFIG_GLOBAL: gitConfig,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0'
  };
  if (process.platform === 'win32') {
    for (const key of ['SystemRoot', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']) {
      const value = process.env[key];
      if (value) env[key] = value;
    }
    env.TEMP ??= privateHome;
    env.TMP ??= privateHome;
  }
  return env;
}

function isWithinDirectory(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

/** @internal Reject package-manager configuration that can run code or redirect resolution. */
export async function assertSafePackageManagerConfiguration(
  root: string,
  manager: Exclude<PackageManager, 'unknown'>
): Promise<void> {
  const rejected = (reason: string): never => {
    throw new ToolipError(
      `The repository's package-manager configuration is not safe for an automated upgrade: ${reason}`,
      { code: 'UPGRADE_PACKAGE_MANAGER_CONFIG_UNSAFE', exitCode: 1 }
    );
  };
  const readConfig = async (
    relativePath: string
  ): Promise<string | undefined> => {
    const file = path.join(root, relativePath);
    try {
      const bytes = await readBoundedRegularFile(file, root, 32_768);
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
      if (isMissingFile(error)) return undefined;
      return rejected(`${relativePath} is not a bounded regular file`);
    }
  };
  const readYamlConfig = async (
    relativePath: string
  ): Promise<Record<string, unknown> | undefined> => {
    const text = await readConfig(relativePath);
    if (text === undefined) return undefined;
    try {
      const document = parseDocument(text, {
        uniqueKeys: true
      });
      if (document.errors.length > 0)
        rejected(`${relativePath} is malformed YAML`);
      const value: unknown = document.toJS({ maxAliasCount: 20 });
      if (value === null) return {};
      if (!value || typeof value !== 'object' || Array.isArray(value))
        rejected(`${relativePath} must contain a YAML mapping`);
      return value as Record<string, unknown>;
    } catch {
      return rejected(`${relativePath} is malformed or unsafe YAML`);
    }
  };
  const hasUnsafeYamlKey = (
    value: unknown,
    unsafeKey: (key: string) => boolean,
    depth = 0
  ): boolean => {
    if (depth > 32 || !value || typeof value !== 'object') return false;
    if (Array.isArray(value))
      return value.some((entry) =>
        hasUnsafeYamlKey(entry, unsafeKey, depth + 1)
      );
    return Object.entries(value).some(
      ([key, entry]) =>
        unsafeKey(key) || hasUnsafeYamlKey(entry, unsafeKey, depth + 1)
    );
  };
  const npmrc = await readConfig('.npmrc');
  if (npmrc) {
    for (const line of npmrc.split(/\r?\n/u)) {
      const active = line.trim();
      if (!active || active.startsWith('#') || active.startsWith(';')) continue;
      const pair = /^([^=]+)=(.*)$/u.exec(active);
      if (pair === null) {
        throw new ToolipError(
          "The repository's package-manager configuration is not safe for an automated upgrade: .npmrc contains an unrecognized directive",
          { code: 'UPGRADE_PACKAGE_MANAGER_CONFIG_UNSAFE', exitCode: 1 }
        );
      }
      const key = pair[1]?.trim().toLowerCase() ?? '';
      const value = pair[2]?.trim() ?? '';
      const normalizedKey = key.replaceAll(/[-_]/gu, '');
      if (
        /(?:_auth|token|password|username|cert|key|proxy|cafile)/u.test(key) ||
        ['configdependencies', 'onloadscript'].includes(normalizedKey)
      )
        rejected(
          '.npmrc contains an executable, authentication or transport override'
        );
      if (key === 'registry' || key.endsWith(':registry')) {
        if (value !== 'https://registry.npmjs.org/')
          rejected('.npmrc selects a non-public npm registry');
      }
    }
  }

  if (manager === 'pnpm') {
    const pnpmConfig = await readYamlConfig('pnpm-workspace.yaml');
    if (
      pnpmConfig &&
      hasUnsafeYamlKey(pnpmConfig, (key) => {
        const normalized = key.toLowerCase().replaceAll(/[-_]/gu, '');
        return (
          normalized === 'pnpmfile' ||
          normalized === 'configdependencies' ||
          normalized === 'registry' ||
          normalized === 'registries' ||
          normalized.endsWith(':registry')
        );
      })
    )
      rejected('pnpm-workspace.yaml changes the package hook or registry');
    for (const file of ['.pnpmfile.cjs', '.pnpmfile.js']) {
      if (await readConfig(file))
        rejected(`${file} can execute during resolution`);
    }
  }

  if (manager === 'yarn') {
    const classic = await readConfig('.yarnrc');
    if (classic && /(?:yarn-path|registry|npmAuth|_auth|token)/iu.test(classic))
      rejected(
        '.yarnrc configures executable shims, authentication or a registry'
      );
    const modern = await readYamlConfig('.yarnrc.yml');
    if (
      modern &&
      hasUnsafeYamlKey(modern, (key) => {
        const normalized = key.toLowerCase().replaceAll(/[-_]/gu, '');
        return (
          normalized === 'yarnpath' ||
          normalized === 'plugins' ||
          normalized.startsWith('npmauth') ||
          normalized === 'npmscopes' ||
          normalized.startsWith('npmregistr')
        );
      })
    )
      rejected('.yarnrc.yml configures plugins, authentication or a registry');
  }
}

function sanitizeBranchPart(value: string): string {
  const sanitized = value
    .replace(/^@/, '')
    .replaceAll(/[^A-Za-z0-9._-]+/g, '-')
    .replaceAll(/^-+|-+$/g, '');

  if (!sanitized) {
    throw new ToolipError(
      'Unable to create a safe branch name for this upgrade.',
      {
        code: 'UPGRADE_BRANCH_INVALID',
        exitCode: 1
      }
    );
  }

  return sanitized;
}

function normalizeGitPath(value: string): string {
  return value.replaceAll('\\', '/');
}

async function bestEffort(operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch {
    // Cleanup errors must not hide the primary operation result.
  }
}
