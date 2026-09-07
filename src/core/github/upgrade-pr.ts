import { execFile } from 'node:child_process';
import {
  mkdtemp,
  readFile,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import semver from 'semver';
import { ToolipError } from '../../errors/toolip-error.js';
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

type CommandResult = {
  stdout: string;
  stderr: string;
};

export type UpgradePrRuntime = {
  exec: (
    command: string,
    args: string[],
    cwd: string
  ) => Promise<CommandResult>;
  makeTempDir: (prefix: string) => Promise<string>;
};

const defaultRuntime: UpgradePrRuntime = {
  async exec(command, args, cwd) {
    const result = await execFileAsync(command, args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024
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
  runtime: UpgradePrRuntime = defaultRuntime
): Promise<{
  branch: string;
  changed: boolean;
  packageManager: Exclude<PackageManager, 'unknown'>;
}> {
  const absoluteRoot = path.resolve(root);
  const normalizedVersion = semver.valid(targetVersion);

  if (!normalizedVersion) {
    throw new ToolipError(
      `Invalid target version: ${targetVersion}. Use an exact semantic version.`,
      {
        code: 'UPGRADE_INVALID_VERSION',
        exitCode: 1
      }
    );
  }

  const repoRoot = await resolveRepositoryRoot(absoluteRoot, runtime);
  const packageRelative = path.relative(repoRoot, absoluteRoot);

  if (packageRelative.startsWith('..') || path.isAbsolute(packageRelative)) {
    throw new ToolipError('Upgrade target must be inside the resolved Git working tree.', {
      code: 'UPGRADE_PATH_OUTSIDE_REPOSITORY',
      exitCode: 1
    });
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

  await requireOrigin(repoRoot, runtime);

  const branchBase =
    `toolip/upgrade-${sanitizeBranchPart(packageName)}-${sanitizeBranchPart(normalizedVersion)}`;
  const branch = await chooseAvailableBranch(repoRoot, branchBase, runtime);

  if (dryRun) {
    return {
      branch,
      changed: true,
      packageManager: manager
    };
  }

  const tempRoot = await runtime.makeTempDir(
    path.join(os.tmpdir(), 'toolip-upgrade-pr-')
  );
  const worktree = path.join(tempRoot, 'worktree');
  const manifestRelative = packageRelative
    ? path.join(packageRelative, 'package.json')
    : 'package.json';
  const worktreeManifest = path.join(worktree, manifestRelative);
  const lockfile = packageManagerLockfile(manager);
  let pushed = false;
  let prCreated = false;

  try {
    await runtime.exec(
      'git',
      ['worktree', 'add', '-b', branch, worktree, 'HEAD'],
      repoRoot
    );

    for (const section of declaredSections) {
      const dependencies = manifest[section];
      if (dependencies) dependencies[packageName] = normalizedVersion;
    }

    await writeFile(
      worktreeManifest,
      `${JSON.stringify(manifest, null, 2)}\n`,
      'utf8'
    );

    await updateLockfile(manager, worktree, runtime);
    await runTests(manager, worktree, runtime);

    await runtime.exec(
      'git',
      ['add', normalizeGitPath(manifestRelative), lockfile],
      worktree
    );
    await runtime.exec(
      'git',
      [
        'commit',
        '-m',
        `chore: upgrade ${packageName} to ${normalizedVersion}`
      ],
      worktree
    );
    await runtime.exec(
      'git',
      ['push', '-u', 'origin', branch],
      worktree
    );
    pushed = true;

    await runtime.exec(
      'gh',
      [
        'pr',
        'create',
        '--head',
        branch,
        '--title',
        `chore: upgrade ${packageName} to ${normalizedVersion}`,
        '--body',
        'Toolip generated this dependency upgrade in an isolated worktree after updating the lockfile and running the project test suite.'
      ],
      worktree
    );
    prCreated = true;

    return {
      branch,
      changed: true,
      packageManager: manager
    };
  } finally {
    await bestEffort(() =>
      runtime.exec('git', ['worktree', 'remove', '--force', worktree], repoRoot)
    );
    await bestEffort(() => rm(tempRoot, { recursive: true, force: true }));
    await bestEffort(() => runtime.exec('git', ['branch', '-D', branch], repoRoot));

    if (pushed && !prCreated) {
      await bestEffort(() =>
        runtime.exec('git', ['push', 'origin', '--delete', branch], repoRoot)
      );
    }
  }
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
    return path.resolve(result.stdout.trim());
  } catch {
    throw new ToolipError('Upgrade PR creation requires a Git working tree.', {
      code: 'UPGRADE_GIT_REQUIRED',
      exitCode: 1
    });
  }
}

async function readManifest(manifestPath: string): Promise<PackageManifest> {
  try {
    return JSON.parse(await readFile(manifestPath, 'utf8')) as PackageManifest;
  } catch {
    throw new ToolipError('Unable to read a valid package.json for the upgrade target.', {
      code: 'UPGRADE_MANIFEST_INVALID',
      exitCode: 1
    });
  }
}

async function requireOrigin(
  repoRoot: string,
  runtime: UpgradePrRuntime
): Promise<void> {
  try {
    await runtime.exec('git', ['remote', 'get-url', 'origin'], repoRoot);
  } catch {
    throw new ToolipError('Upgrade PR creation requires an origin Git remote.', {
      code: 'UPGRADE_ORIGIN_REQUIRED',
      exitCode: 1
    });
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

async function updateLockfile(
  manager: Exclude<PackageManager, 'unknown'>,
  cwd: string,
  runtime: UpgradePrRuntime
): Promise<void> {
  if (manager === 'npm') {
    await runtime.exec(
      'npm',
      ['install', '--package-lock-only', '--ignore-scripts'],
      cwd
    );
    return;
  }

  if (manager === 'pnpm') {
    await runtime.exec(
      'pnpm',
      ['install', '--lockfile-only', '--ignore-scripts'],
      cwd
    );
    return;
  }

  const version = await runtime.exec('yarn', ['--version'], cwd);
  const major = Number.parseInt(version.stdout.trim().split('.')[0] ?? '', 10);

  if (Number.isInteger(major) && major >= 2) {
    await runtime.exec('yarn', ['install', '--mode=update-lockfile'], cwd);
    return;
  }

  await runtime.exec(
    'yarn',
    ['install', '--ignore-scripts', '--non-interactive'],
    cwd
  );
}

async function runTests(
  manager: Exclude<PackageManager, 'unknown'>,
  cwd: string,
  runtime: UpgradePrRuntime
): Promise<void> {
  await runtime.exec(manager, ['test'], cwd);
}

function sanitizeBranchPart(value: string): string {
  const sanitized = value
    .replace(/^@/, '')
    .replaceAll(/[^A-Za-z0-9._-]+/g, '-')
    .replaceAll(/^-+|-+$/g, '');

  if (!sanitized) {
    throw new ToolipError('Unable to create a safe branch name for this upgrade.', {
      code: 'UPGRADE_BRANCH_INVALID',
      exitCode: 1
    });
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
