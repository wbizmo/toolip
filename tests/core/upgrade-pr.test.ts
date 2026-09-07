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
import { describe, expect, it } from 'vitest';
import {
  createUpgradePullRequest,
  type UpgradePrRuntime
} from '../../src/core/github/upgrade-pr.js';

const execFileAsync = promisify(execFile);

describe('createUpgradePullRequest', () => {
  it('uses an isolated worktree and preserves a dirty original working tree', async () => {
    const fixture = await createRepositoryFixture();
    const ghCalls: string[][] = [];

    try {
      await writeFile(
        path.join(fixture.root, 'local-notes.txt'),
        'keep my dirty worktree',
        'utf8'
      );
      const originalBranch = await git(fixture.root, ['branch', '--show-current']);
      const runtime = createRuntime({ ghCalls });

      const result = await createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.0.0',
        false,
        runtime
      );

      expect(result.packageManager).toBe('npm');
      expect(result.branch).toBe('toolip/upgrade-example-package-2.0.0');
      expect(await git(fixture.root, ['branch', '--show-current'])).toBe(originalBranch);
      expect(await readFile(path.join(fixture.root, 'local-notes.txt'), 'utf8'))
        .toBe('keep my dirty worktree');
      expect(await git(fixture.root, ['status', '--porcelain']))
        .toContain('?? local-notes.txt');
      expect(await git(fixture.root, ['worktree', 'list', '--porcelain']))
        .not.toContain('toolip-upgrade-pr-');
      expect(await git(fixture.root, ['branch', '--list', result.branch])).toBe('');
      expect(
        await git(fixture.root, ['ls-remote', '--heads', 'origin', `refs/heads/${result.branch}`])
      ).toContain(`refs/heads/${result.branch}`);
      expect(ghCalls.some((args) => args.slice(0, 2).join(' ') === 'pr create')).toBe(true);
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });

  it('cleans up after a failed test without changing the original branch or dirty files', async () => {
    const fixture = await createRepositoryFixture();

    try {
      await writeFile(path.join(fixture.root, 'dirty.txt'), 'unchanged', 'utf8');
      const originalBranch = await git(fixture.root, ['branch', '--show-current']);
      const runtime = createRuntime({ failTests: true });

      await expect(
        createUpgradePullRequest(
          fixture.root,
          'example-package',
          '2.0.0',
          false,
          runtime
        )
      ).rejects.toThrow('simulated test failure');

      expect(await git(fixture.root, ['branch', '--show-current'])).toBe(originalBranch);
      expect(await readFile(path.join(fixture.root, 'dirty.txt'), 'utf8')).toBe('unchanged');
      expect(await git(fixture.root, ['status', '--porcelain'])).toContain('?? dirty.txt');
      expect(await git(fixture.root, ['branch', '--list', 'toolip/upgrade-example-package-2.0.0']))
        .toBe('');
      expect(
        await git(
          fixture.root,
          ['ls-remote', '--heads', 'origin', 'refs/heads/toolip/upgrade-example-package-2.0.0']
        )
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

      await git(
        fixture.root,
        ['branch', 'toolip/upgrade-example-package-2.0.0']
      );

      const dryRun = await createUpgradePullRequest(
        fixture.root,
        'example-package',
        '2.0.0',
        true,
        runtime
      );

      expect(dryRun.branch).toBe('toolip/upgrade-example-package-2.0.0-2');
      expect(await git(fixture.root, ['worktree', 'list', '--porcelain']))
        .not.toContain('toolip-upgrade-pr-');
    } finally {
      await rm(fixture.container, { recursive: true, force: true });
    }
  });
});

function createRuntime(options: {
  failTests?: boolean;
  ghCalls?: string[][];
}): UpgradePrRuntime {
  return {
    makeTempDir: mkdtemp,
    async exec(command, args, cwd) {
      if (command === 'npm') {
        if (args[0] === 'test' && options.failTests) {
          throw new Error('simulated test failure');
        }
        return { stdout: '', stderr: '' };
      }

      if (command === 'gh') {
        options.ghCalls?.push(args);
        return { stdout: 'https://github.example/pr/1\n', stderr: '' };
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
  const container = await mkdtemp(path.join(os.tmpdir(), 'toolip-upgrade-fixture-'));
  const root = path.join(container, 'repo');
  const remote = path.join(container, 'remote.git');

  await execFileAsync('git', ['init', root]);
  await execFileAsync('git', ['init', '--bare', remote]);
  await execFileAsync('git', ['config', 'user.name', 'Toolip Test'], { cwd: root });
  await execFileAsync('git', ['config', 'user.email', 'toolip@example.test'], { cwd: root });
  await writeFile(
    path.join(root, 'package.json'),
    `${JSON.stringify({
      name: 'fixture',
      version: '1.0.0',
      dependencies: {
        'example-package': '1.0.0'
      },
      scripts: {
        test: 'echo ok'
      }
    }, null, 2)}\n`,
    'utf8'
  );
  await writeFile(
    path.join(root, 'package-lock.json'),
    `${JSON.stringify({
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
    }, null, 2)}\n`,
    'utf8'
  );
  await git(root, ['add', '.']);
  await git(root, ['commit', '-m', 'initial']);
  await git(root, ['remote', 'add', 'origin', remote]);

  return { container, root };
}

async function git(root: string, args: string[]): Promise<string> {
  const result = await execFileAsync('git', args, {
    cwd: root,
    encoding: 'utf8'
  });
  return String(result.stdout ?? '').trim();
}
