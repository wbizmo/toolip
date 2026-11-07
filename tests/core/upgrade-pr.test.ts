import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';
import type { Finding } from '../../src/contracts/finding.js';
import {
  createUpgradePullRequest,
  installFrozenDependencies,
  type UpgradeSecurityAssessment,
  type UpgradePrRuntime
} from '../../src/core/github/upgrade-pr.js';

const execFileAsync = promisify(execFile);

describe('createUpgradePullRequest', () => {
  it('runs a devDependency-provided test executable after frozen install in a real worktree', async () => {
    const container = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-upgrade-real-install-')
    );
    const root = path.join(container, 'repo');
    const worktree = path.join(container, 'worktree');
    let worktreeAdded = false;
    const runtime: UpgradePrRuntime = {
      makeTempDir: mkdtemp,
      async exec(command, args, cwd) {
        const result = await execFileAsync(command, args, {
          cwd,
          encoding: 'utf8',
          timeout: 60_000,
          maxBuffer: 4 * 1024 * 1024
        });
        return {
          stdout: String(result.stdout ?? ''),
          stderr: String(result.stderr ?? '')
        };
      }
    };

    try {
      await mkdir(root, { recursive: true });
      await mkdir(path.join(root, 'fixture-cli/bin'), { recursive: true });
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify(
          {
            name: 'upgrade-real-install-fixture',
            version: '1.0.0',
            scripts: { test: 'fixture-check' },
            devDependencies: { 'fixture-cli': 'file:./fixture-cli' }
          },
          null,
          2
        )
      );
      await writeFile(
        path.join(root, 'fixture-cli/package.json'),
        JSON.stringify(
          {
            name: 'fixture-cli',
            version: '1.0.0',
            bin: { 'fixture-check': './bin/check.js' }
          },
          null,
          2
        )
      );
      await writeFile(
        path.join(root, 'fixture-cli/bin/check.js'),
        '#!/usr/bin/env node\nrequire("node:fs").writeFileSync("fixture-test-ran", "yes");\n'
      );
      await chmod(path.join(root, 'fixture-cli/bin/check.js'), 0o755);
      await runtime.exec(
        'npm',
        ['install', '--package-lock-only', '--ignore-scripts'],
        root
      );
      await runtime.exec('git', ['init', root], container);
      await runtime.exec('git', ['config', 'user.name', 'Toolip Test'], root);
      await runtime.exec(
        'git',
        ['config', 'user.email', 'toolip@example.test'],
        root
      );
      await runtime.exec('git', ['add', '.'], root);
      await runtime.exec('git', ['commit', '-m', 'fixture'], root);
      await runtime.exec(
        'git',
        ['worktree', 'add', '-b', 'upgrade-fixture', worktree, 'HEAD'],
        root
      );
      worktreeAdded = true;

      await installFrozenDependencies('npm', worktree, runtime);
      await runtime.exec('npm', ['test'], worktree);
      expect(
        await realpath(path.join(worktree, 'node_modules/.bin/fixture-check'))
      ).toBe(
        await realpath(
          path.join(worktree, 'node_modules/fixture-cli/bin/check.js')
        )
      );
      expect(
        await readFile(path.join(worktree, 'fixture-test-ran'), 'utf8')
      ).toBe('yes');
    } finally {
      if (worktreeAdded) {
        await runtime
          .exec('git', ['worktree', 'remove', '--force', worktree], root)
          .catch(() => undefined);
      }
      await rm(container, { recursive: true, force: true });
    }
  }, 60_000);

  it('uses frozen no-script install flags for pnpm and both Yarn generations', async () => {
    const calls: string[][] = [];
    let yarnVersion = '1.22.22';
    const runtime: UpgradePrRuntime = {
      makeTempDir: mkdtemp,
      async exec(command, args) {
        calls.push([command, ...args]);
        if (command === 'yarn' && args[0] === '--version') {
          return { stdout: yarnVersion, stderr: '' };
        }
        return { stdout: '', stderr: '' };
      }
    };

    await installFrozenDependencies('pnpm', '/tmp/worktree', runtime);
    expect(calls.at(-1)).toEqual([
      'pnpm',
      'install',
      '--frozen-lockfile',
      '--ignore-scripts'
    ]);

    await installFrozenDependencies('yarn', '/tmp/worktree', runtime);
    expect(calls.at(-1)).toEqual([
      'yarn',
      'install',
      '--frozen-lockfile',
      '--ignore-scripts',
      '--non-interactive'
    ]);

    yarnVersion = '4.5.0';
    await installFrozenDependencies('yarn', '/tmp/worktree', runtime);
    expect(calls.at(-1)).toEqual([
      'yarn',
      'install',
      '--immutable',
      '--mode=skip-builds'
    ]);
  });

  it('uses an isolated worktree and preserves a dirty original working tree', async () => {
    const fixture = await createRepositoryFixture();
    const ghCalls: string[][] = [];
    const npmCalls: string[][] = [];

    try {
      await writeFile(
        path.join(fixture.root, 'local-notes.txt'),
        'keep my dirty worktree',
        'utf8'
      );
      const originalBranch = await git(fixture.root, [
        'branch',
        '--show-current'
      ]);
      const runtime = createRuntime({ ghCalls, npmCalls });

      const result = await createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.0.0',
        false,
        runtime,
        undefined,
        { allowProjectTests: true }
      );

      expect(result.packageManager).toBe('npm');
      expect(result.branch).toBe('toolip/upgrade-example-package-2.0.0');
      expect(await git(fixture.root, ['branch', '--show-current'])).toBe(
        originalBranch
      );
      expect(
        await readFile(path.join(fixture.root, 'local-notes.txt'), 'utf8')
      ).toBe('keep my dirty worktree');
      expect(await git(fixture.root, ['status', '--porcelain'])).toContain(
        '?? local-notes.txt'
      );
      expect(
        await git(fixture.root, ['worktree', 'list', '--porcelain'])
      ).not.toContain('toolip-upgrade-pr-');
      expect(await git(fixture.root, ['branch', '--list', result.branch])).toBe(
        ''
      );
      expect(
        await git(fixture.root, [
          'ls-remote',
          '--heads',
          'origin',
          `refs/heads/${result.branch}`
        ])
      ).toContain(`refs/heads/${result.branch}`);
      expect(
        ghCalls.some((args) => args.slice(0, 2).join(' ') === 'pr create')
      ).toBe(true);
      const prBody = ghCalls
        .find((args) => args[0] === 'pr' && args[1] === 'create')
        ?.at(-1);
      expect(prBody).toContain(
        'Complete baseline and candidate Toolip security assessments passed.'
      );
      expect(prBody).toContain('Human review is required');
      expect(npmCalls.filter((args) => args[0] === 'ci')).toHaveLength(2);
      expect(
        npmCalls.findIndex((args) => args[0] === 'ci')
      ).toBeGreaterThanOrEqual(0);
      expect(npmCalls.findIndex((args) => args[0] === 'ci')).toBeLessThan(
        npmCalls.findIndex((args) => args[0] === 'test')
      );
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  }, 15_000);

  it('cleans up after a failed test without changing the original branch or dirty files', async () => {
    const fixture = await createRepositoryFixture();
    const effects: string[] = [];

    try {
      await writeFile(
        path.join(fixture.root, 'dirty.txt'),
        'unchanged',
        'utf8'
      );
      const originalBranch = await git(fixture.root, [
        'branch',
        '--show-current'
      ]);
      const runtime = createRuntime({ failTests: true, effects });

      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          runtime,
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toThrow('simulated test failure');

      expect(await git(fixture.root, ['branch', '--show-current'])).toBe(
        originalBranch
      );
      expect(await readFile(path.join(fixture.root, 'dirty.txt'), 'utf8')).toBe(
        'unchanged'
      );
      expect(await git(fixture.root, ['status', '--porcelain'])).toContain(
        '?? dirty.txt'
      );
      expect(
        await git(fixture.root, [
          'branch',
          '--list',
          'toolip/upgrade-example-package-2.0.0'
        ])
      ).toBe('');
      expect(effects).toEqual([]);
      expect(
        await git(fixture.root, [
          'ls-remote',
          '--heads',
          'origin',
          'refs/heads/toolip/upgrade-example-package-2.0.0'
        ])
      ).toBe('');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('deletes a pushed branch only after GitHub confirms PR creation did not succeed', async () => {
    for (const existingPullRequest of [false, true, undefined] as const) {
      const fixture = await createRepositoryFixture();
      const branch = 'toolip/upgrade-example-package-2.0.0';
      try {
        await expect(
          createUpgradePullRequest(
            fixture.root,
            'example-package',
            '2.0.0',
            false,
            createRuntime({
              failPrCreation: true,
              existingPullRequest
            }),
            undefined,
            { allowProjectTests: true }
          )
        ).rejects.toThrow('simulated PR creation failure');
        const remoteBranch = await git(fixture.root, [
          'ls-remote',
          '--heads',
          'origin',
          `refs/heads/${branch}`
        ]);
        expect(remoteBranch.length > 0).toBe(existingPullRequest !== false);
      } finally {
        await rm(fixture.container, { recursive: true, force: true });
      }
    }
  });

  it('blocks push and PR creation when frozen dependency installation fails', async () => {
    const fixture = await createRepositoryFixture();
    const effects: string[] = [];
    try {
      const originalBranch = await git(fixture.root, [
        'branch',
        '--show-current'
      ]);
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          createRuntime({ failInstall: true, effects }),
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toThrow('simulated install failure');
      expect(effects).toEqual([]);
      expect(await git(fixture.root, ['branch', '--show-current'])).toBe(
        originalBranch
      );
      expect(
        await git(fixture.root, [
          'branch',
          '--list',
          'toolip/upgrade-example-package-2.0.0'
        ])
      ).toBe('');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('aborts a running install and cleans the worktree before returning', async () => {
    const fixture = await createRepositoryFixture();
    const controller = new AbortController();
    const effects: string[] = [];
    let markInstallStarted!: () => void;
    const installStarted = new Promise<void>((resolve) => {
      markInstallStarted = resolve;
    });
    try {
      const operation = createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.0.0',
        false,
        createRuntime({ effects, waitOnInstall: markInstallStarted }),
        controller.signal,
        { allowProjectTests: true }
      );
      await installStarted;
      controller.abort();
      await expect(operation).rejects.toBeDefined();
      expect(effects).toEqual([]);
      expect(
        await git(fixture.root, ['worktree', 'list', '--porcelain'])
      ).not.toContain('toolip-upgrade-pr-');
      expect(
        await git(fixture.root, [
          'branch',
          '--list',
          'toolip/upgrade-example-package-2.0.0'
        ])
      ).toBe('');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('rejects invalid versions before mutation and allocates around branch collisions', async () => {
    const fixture = await createRepositoryFixture();

    try {
      const runtime = createRuntime({});

      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          'latest',
          true,
          runtime
        )
      ).rejects.toMatchObject({ code: 'UPGRADE_INVALID_VERSION' });

      await git(fixture.root, [
        'branch',
        'toolip/upgrade-example-package-2.0.0'
      ]);

      const dryRun = await createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.0.0',
        true,
        runtime
      );

      expect(dryRun.branch).toBe('toolip/upgrade-example-package-2.0.0-2');
      expect(
        await git(fixture.root, ['worktree', 'list', '--porcelain'])
      ).not.toContain('toolip-upgrade-pr-');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('requires explicit approval before running repository-defined tests', async () => {
    const fixture = await createRepositoryFixture();
    const effects: string[] = [];
    try {
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          createRuntime({ effects })
        )
      ).rejects.toMatchObject({ code: 'UPGRADE_PROJECT_TESTS_NOT_APPROVED' });
      expect(effects).toEqual([]);
      expect(
        await git(fixture.root, [
          'branch',
          '--list',
          'toolip/upgrade-example-package-2.0.0'
        ])
      ).toBe('');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('blocks before remote publication when the baseline assessment is incomplete', async () => {
    const fixture = await createRepositoryFixture();
    const effects: string[] = [];
    const assessments: UpgradeSecurityAssessment[] = [
      {
        analysis: { state: 'partial', reasons: ['provider unavailable'] },
        findings: [],
        coverage: { eligible: 3, scanned: 2 }
      }
    ];
    try {
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          createRuntime({ effects, assessments }),
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toMatchObject({
        code: 'UPGRADE_SECURITY_ASSESSMENT_INCOMPLETE'
      });
      expect(effects).toEqual([]);
      expect(
        await git(fixture.root, ['worktree', 'list', '--porcelain'])
      ).not.toContain('toolip-upgrade-pr-');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('blocks policy regressions before push', async () => {
    const fixture = await createRepositoryFixture();
    const effects: string[] = [];
    const introduced: Finding = {
      id: 'TLP-NEW-HIGH-FINDING',
      ruleId: 'TLP-TEST-001',
      title: 'New blocking finding',
      category: 'dangerous-code',
      severity: 'high',
      confidence: 'high',
      message: 'Synthetic test finding',
      source: 'test'
    };
    try {
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          createRuntime({
            effects,
            assessments: [
              completeAssessment(),
              { ...completeAssessment(), findings: [introduced] }
            ]
          }),
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toMatchObject({ code: 'UPGRADE_POLICY_REGRESSION' });
      expect(effects).toEqual([]);
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('creates evidence only after the candidate removes the exact advisory and reaches a fixed version', async () => {
    const fixture = await createRepositoryFixture();
    const ghCalls: string[][] = [];
    try {
      const result = await createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.1.0',
        false,
        createRuntime({
          ghCalls,
          assessments: [
            {
              ...completeAssessment(),
              findings: [targetAdvisory('GHSA-upgrade-test', ['2.0.0'])]
            },
            completeAssessment()
          ]
        }),
        undefined,
        { allowProjectTests: true }
      );
      expect(result.verification).toMatchObject({
        targetVulnerabilitiesBefore: 1,
        targetVulnerabilitiesResolved: 1,
        targetVulnerabilitiesRemaining: 0
      });
      expect(ghCalls.at(-1)?.at(-1)).toContain('1 resolved, 0 remaining');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('rejects a target below the advisory fixed version before pushing', async () => {
    const fixture = await createRepositoryFixture();
    const effects: string[] = [];
    try {
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '1.5.0',
          false,
          createRuntime({
            effects,
            assessments: [
              {
                ...completeAssessment(),
                findings: [targetAdvisory('GHSA-upgrade-test', ['2.0.0'])]
              },
              completeAssessment()
            ]
          }),
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toMatchObject({ code: 'UPGRADE_TARGET_NOT_VERIFIED_FIX' });
      expect(effects).toEqual([]);
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('blocks project tests that alter the lockfile after exact resolution', async () => {
    const fixture = await createRepositoryFixture();
    const effects: string[] = [];
    try {
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          createRuntime({ effects, mutateLockAfterTests: true }),
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toMatchObject({
        code: 'UPGRADE_INPUTS_CHANGED_DURING_TEST'
      });
      expect(effects).toEqual([]);
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('rejects dirty package manifests and lockfiles before creating a worktree', async () => {
    const fixture = await createRepositoryFixture();
    try {
      const manifest = JSON.parse(
        await readFile(path.join(fixture.root, 'package.json'), 'utf8')
      ) as { dependencies: Record<string, string> };
      manifest.dependencies['example-package'] = '1.0.1';
      await writeFile(
        path.join(fixture.root, 'package.json'),
        `${JSON.stringify(manifest, null, 2)}\n`
      );
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          createRuntime({}),
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toMatchObject({ code: 'UPGRADE_INPUTS_DIRTY' });
      expect(
        await git(fixture.root, ['worktree', 'list', '--porcelain'])
      ).not.toContain('toolip-upgrade-pr-');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('does not execute caller repository Git hooks while creating or committing the upgrade worktree', async () => {
    const fixture = await createRepositoryFixture();
    const marker = path.join(fixture.container, 'git-hook-ran');
    try {
      const hooks = await git(fixture.root, [
        'rev-parse',
        '--git-path',
        'hooks'
      ]);
      const hookPath = path.join(fixture.root, hooks, 'post-checkout');
      await writeFile(hookPath, `#!/bin/sh\nprintf ran > '${marker}'\n`);
      await chmod(hookPath, 0o755);
      await createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.0.0',
        false,
        createRuntime({}),
        undefined,
        { allowProjectTests: true }
      );
      expect(existsSync(marker)).toBe(false);
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('does not pass host credentials or Node options to package-manager commands', async () => {
    const fixture = await createRepositoryFixture();
    const environments: NodeJS.ProcessEnv[] = [];
    try {
      await createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.0.0',
        false,
        createRuntime({ environments }),
        undefined,
        { allowProjectTests: true }
      );
      expect(environments.length).toBeGreaterThan(0);
      for (const env of environments) {
        expect(env.NODE_AUTH_TOKEN).toBeUndefined();
        expect(env.NPM_TOKEN).toBeUndefined();
        expect(env.GITHUB_TOKEN).toBeUndefined();
        expect(env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
        expect(env.NODE_OPTIONS).toBeUndefined();
        expect(env.HOME).not.toBe(process.env.HOME);
        expect(env.NPM_CONFIG_REGISTRY).toBe('https://registry.npmjs.org/');
      }
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('rejects package-manager auth configuration before installing dependencies', async () => {
    const fixture = await createRepositoryFixture();
    const npmCalls: string[][] = [];
    try {
      await writeFile(
        path.join(fixture.root, '.npmrc'),
        '//registry.npmjs.org/:_authToken=repository-secret\n'
      );
      await git(fixture.root, ['add', '.npmrc']);
      await git(fixture.root, ['commit', '-m', 'add package manager config']);
      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          createRuntime({ npmCalls }),
          undefined,
          { allowProjectTests: true }
        )
      ).rejects.toMatchObject({
        code: 'UPGRADE_PACKAGE_MANAGER_CONFIG_UNSAFE'
      });
      expect(npmCalls).toEqual([]);
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });
});

function createRuntime(options: {
  failTests?: boolean;
  failInstall?: boolean;
  failPrCreation?: boolean;
  existingPullRequest?: boolean;
  waitOnInstall?: () => void;
  ghCalls?: string[][];
  npmCalls?: string[][];
  effects?: string[];
  assessments?: UpgradeSecurityAssessment[];
  mutateLockAfterTests?: boolean;
  environments?: NodeJS.ProcessEnv[];
}): UpgradePrRuntime {
  let assessmentIndex = 0;
  return {
    makeTempDir: mkdtemp,
    async assess() {
      return options.assessments?.[assessmentIndex++] ?? completeAssessment();
    },
    async exec(command, args, cwd, signal, env) {
      if (command === 'npm') {
        if (env) options.environments?.push(env);
        options.npmCalls?.push(args);
        if (args[0] === 'ci' && options.failInstall) {
          throw new Error('simulated install failure');
        }
        if (args[0] === 'ci' && options.waitOnInstall) {
          options.waitOnInstall();
          return await new Promise((_resolve, reject) => {
            signal?.addEventListener(
              'abort',
              () => reject(new Error('simulated install cancellation')),
              { once: true }
            );
          });
        }
        if (args[0] === 'test' && options.failTests) {
          throw new Error('simulated test failure');
        }
        if (args[0] === 'test' && options.mutateLockAfterTests) {
          const lock = JSON.parse(
            await readFile(path.join(cwd, 'package-lock.json'), 'utf8')
          ) as {
            packages: Record<string, { version?: string }>;
          };
          const entry = lock.packages['node_modules/example-package'];
          if (!entry) throw new Error('fixture lock entry is missing');
          entry.version = '9.9.9';
          await writeFile(
            path.join(cwd, 'package-lock.json'),
            `${JSON.stringify(lock, null, 2)}\n`
          );
        }
        if (args[0] === 'install' && args.includes('--package-lock-only')) {
          const manifest = JSON.parse(
            await readFile(path.join(cwd, 'package.json'), 'utf8')
          ) as {
            dependencies?: Record<string, string>;
          };
          const lock = JSON.parse(
            await readFile(path.join(cwd, 'package-lock.json'), 'utf8')
          ) as {
            packages: Record<string, { version?: string }>;
          };
          for (const [name, version] of Object.entries(
            manifest.dependencies ?? {}
          )) {
            const entry = lock.packages[`node_modules/${name}`];
            if (entry) entry.version = version;
          }
          await writeFile(
            path.join(cwd, 'package-lock.json'),
            `${JSON.stringify(lock, null, 2)}\n`
          );
        }
        return { stdout: '', stderr: '' };
      }

      if (command === 'gh') {
        options.effects?.push('pr');
        options.ghCalls?.push(args);
        if (args[0] === 'pr' && args[1] === 'create' && options.failPrCreation)
          throw new Error('simulated PR creation failure');
        if (args[0] === 'pr' && args[1] === 'list') {
          if (options.existingPullRequest === undefined)
            throw new Error('simulated GitHub query failure');
          return {
            stdout: options.existingPullRequest ? '[{"number":1}]' : '[]',
            stderr: ''
          };
        }
        return { stdout: 'https://github.example/pr/1\n', stderr: '' };
      }

      if (command === 'git' && args.includes('push')) {
        options.effects?.push('push');
      }

      const result = await execFileAsync(command, args, {
        cwd,
        encoding: 'utf8'
      });
      return {
        stdout: String(result.stdout ?? ''),
        stderr: String(result.stderr ?? '')
      };
    }
  };
}

async function createRepositoryFixture(): Promise<{
  container: string;
  root: string;
}> {
  const container = await mkdtemp(
    path.join(os.tmpdir(), 'toolip-upgrade-fixture-')
  );
  const root = path.join(container, 'repo');
  const remote = path.join(container, 'remote.git');

  await execFileAsync('git', ['init', root]);
  await execFileAsync('git', ['init', '--bare', remote]);
  await execFileAsync('git', ['config', 'user.name', 'Toolip Test'], {
    cwd: root
  });
  await execFileAsync('git', ['config', 'user.email', 'toolip@example.test'], {
    cwd: root
  });
  await writeFile(
    path.join(root, 'package.json'),
    `${JSON.stringify(
      {
        name: 'fixture',
        version: '1.0.0',
        dependencies: {
          'example-package': '1.0.0'
        },
        scripts: {
          test: 'echo ok'
        }
      },
      null,
      2
    )}\n`,
    'utf8'
  );
  await writeFile(
    path.join(root, 'package-lock.json'),
    `${JSON.stringify(
      {
        name: 'fixture',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: { 'example-package': '1.0.0' }
          },
          'node_modules/example-package': {
            version: '1.0.0'
          }
        }
      },
      null,
      2
    )}\n`,
    'utf8'
  );
  await git(root, ['add', '.']);
  await git(root, ['commit', '-m', 'initial']);
  await git(root, ['remote', 'add', 'origin', remote]);

  return { container, root };
}

function completeAssessment(): UpgradeSecurityAssessment {
  return {
    analysis: { state: 'complete', reasons: [] },
    findings: [],
    coverage: { eligible: 10, scanned: 10 }
  };
}

function targetAdvisory(
  vulnerabilityId: string,
  fixedVersions: string[]
): Finding {
  return {
    id: `TLP-CVE-EXAMPLE-PACKAGE-${vulnerabilityId}`,
    ruleId: 'TLP-CVE-001',
    title: 'Synthetic dependency advisory',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'high',
    message: 'Synthetic test advisory',
    source: 'osv',
    remediation: {
      summary: 'Upgrade to a fixed version',
      fixedVersion: fixedVersions[0]
    },
    metadata: {
      package: 'example-package',
      vulnerabilityId,
      remediationPath: { fixedVersions }
    }
  };
}

async function git(root: string, args: string[]): Promise<string> {
  const result = await execFileAsync('git', args, {
    cwd: root,
    encoding: 'utf8'
  });
  return String(result.stdout ?? '').trim();
}
