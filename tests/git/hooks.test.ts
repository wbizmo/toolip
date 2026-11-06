import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync
} from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  installPreCommitHook,
  installPreCommitHookDetailed
} from '../../src/core/hooks.js';
import {
  cleanupRepos,
  git,
  gitEnv,
  makeRepo,
  tempDir,
  write
} from '../helpers/git-repo.js';

afterEach(cleanupRepos);

const BLOCK_START = '# >>> toolip managed pre-commit >>>';
const count = (text: string, needle: string) => text.split(needle).length - 1;
const posix = process.platform !== 'win32';

function runHook(
  hook: string,
  cwd: string,
  extraPath: string,
  env: NodeJS.ProcessEnv = {}
) {
  return spawnSync('sh', [hook], {
    cwd,
    encoding: 'utf8',
    env: {
      ...gitEnv(),
      PATH: `${extraPath}${path.delimiter}/usr/bin${path.delimiter}/bin`,
      ...env
    }
  });
}

function stubBin(dir: string, name: string, body: string): string {
  const bin = path.join(dir, 'bin');
  mkdirSync(bin, { recursive: true });
  const file = path.join(bin, name);
  writeFileSync(file, `#!/bin/sh\n${body}\n`);
  chmodSync(file, 0o755);
  return bin;
}

describe('hook installation (issue #41)', () => {
  it('installs into .git/hooks, preserves user logic and is idempotent', async () => {
    const root = makeRepo();
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    mkdirSync(path.dirname(hook), { recursive: true });
    writeFileSync(hook, '#!/bin/sh\necho "existing hook"\nrun-lint\n', {
      mode: 0o755
    });

    await installPreCommitHook(root);
    const first = readFileSync(hook, 'utf8');
    await installPreCommitHook(root);
    const second = readFileSync(hook, 'utf8');

    expect(second).toBe(first); // byte-identical on re-run
    expect(count(second, BLOCK_START)).toBe(1);
    expect(second).toContain('echo "existing hook"');
    expect(second).toContain('run-lint');
    expect(second).toContain('./node_modules/.bin/toolip');
    expect(second).not.toMatch(/npx\s+toolip/u);
    expect(second.startsWith('#!/bin/sh\n')).toBe(true);
    if (posix) expect(statSync(hook).mode & 0o111).not.toBe(0);
    expect(
      readdirSync(path.dirname(hook)).filter((f) => f.endsWith('.tmp'))
    ).toEqual([]);
  }, 30_000);

  it('places the block before user logic so an early exit cannot bypass it', async () => {
    const root = makeRepo();
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    mkdirSync(path.dirname(hook), { recursive: true });
    writeFileSync(hook, '#!/bin/sh\necho user\nexit 0\n', { mode: 0o755 });

    await installPreCommitHook(root);
    const content = readFileSync(hook, 'utf8');
    expect(content.indexOf(BLOCK_START)).toBeLessThan(
      content.indexOf('exit 0')
    );
  }, 30_000);

  it.skipIf(!posix)(
    'a failing Toolip check still blocks despite the user `exit 0`',
    async () => {
      const root = makeRepo();
      const hook = path.join(root, '.git', 'hooks', 'pre-commit');
      mkdirSync(path.dirname(hook), { recursive: true });
      writeFileSync(hook, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      await installPreCommitHook(root);

      const bin = stubBin(tempDir(), 'toolip', 'exit 7');
      expect(runHook(hook, root, bin).status).toBe(7);
    },
    30_000
  );

  it('migrates an older install that appended the block after an exit', async () => {
    const root = makeRepo();
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    mkdirSync(path.dirname(hook), { recursive: true });
    writeFileSync(
      hook,
      `#!/bin/sh\necho user\nexit 0\n\n${BLOCK_START}\nold\n# <<< toolip managed pre-commit <<<\n`,
      { mode: 0o755 }
    );

    await installPreCommitHook(root);
    const content = readFileSync(hook, 'utf8');
    expect(count(content, BLOCK_START)).toBe(1);
    expect(content).not.toContain('\nold\n');
    expect(content.indexOf(BLOCK_START)).toBeLessThan(
      content.indexOf('exit 0')
    );
  }, 30_000);

  it('honors a relative and an absolute core.hooksPath', async () => {
    const relativeRoot = makeRepo();
    git(relativeRoot, 'config', 'core.hooksPath', '.githooks');
    const relative = await installPreCommitHookDetailed(relativeRoot);
    expect(relative.hookPath).toBe(
      path.join(relativeRoot, '.githooks', 'pre-commit')
    );
    expect(relative.source).toBe('core.hooksPath');
    expect(
      existsSync(path.join(relativeRoot, '.git', 'hooks', 'pre-commit'))
    ).toBe(false);

    const absoluteRoot = makeRepo();
    const shared = path.join(tempDir('toolip-shared-hooks-'), 'hooks');
    git(absoluteRoot, 'config', 'core.hooksPath', shared);
    expect((await installPreCommitHookDetailed(absoluteRoot)).hookPath).toBe(
      path.join(shared, 'pre-commit')
    );
  }, 30_000);

  it('installs into the shared hooks directory from a linked worktree', async () => {
    const root = makeRepo();
    const worktree = path.join(tempDir('toolip-wt-'), 'wt');
    git(root, 'worktree', 'add', '-q', '-b', 'wt-branch', worktree);

    const result = await installPreCommitHookDetailed(worktree);
    const expected = path.resolve(
      worktree,
      git(worktree, 'rev-parse', '--git-path', 'hooks').trim()
    );
    expect(result.hookPath).toBe(path.join(expected, 'pre-commit'));
    expect(result.hookPath).toContain(path.join(root, '.git'));
    expect(existsSync(path.join(worktree, '.git', 'hooks'))).toBe(false); // .git is a file there
  }, 30_000);

  it('redirects Husky generated hooks to the user-editable file and warns', async () => {
    const root = makeRepo();
    const generated = path.join(root, '.husky', '_');
    mkdirSync(generated, { recursive: true });
    // Husky v9 dispatcher: `_/pre-commit` sources the helper `_/h`.
    writeFileSync(
      path.join(generated, 'pre-commit'),
      '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
      { mode: 0o755 }
    );
    writeFileSync(path.join(generated, 'h'), '#!/usr/bin/env sh\n# HUSKY\n', {
      mode: 0o755
    });
    git(root, 'config', 'core.hooksPath', '.husky/_');

    const result = await installPreCommitHookDetailed(root);
    expect(result.hookPath).toBe(path.join(root, '.husky', 'pre-commit'));
    expect(result.warnings.join('\n')).toMatch(/husky/iu);
  }, 30_000);

  it('fails with remediation when the Husky dispatcher is missing or not executable', async () => {
    const root = makeRepo();
    const generated = path.join(root, '.husky', '_');
    mkdirSync(generated, { recursive: true });
    git(root, 'config', 'core.hooksPath', '.husky/_');

    // Missing entirely.
    await expect(installPreCommitHookDetailed(root)).rejects.toMatchObject({
      code: 'HOOK_HUSKY_DISPATCHER_MISSING'
    });
    expect(existsSync(path.join(root, '.husky', 'pre-commit'))).toBe(false);

    // Present but not executable (POSIX only: mode bits are not enforced on Windows).
    if (posix) {
      writeFileSync(path.join(generated, 'pre-commit'), '#!/bin/sh\n', {
        mode: 0o644
      });
      writeFileSync(path.join(generated, 'h'), '#!/bin/sh\n', { mode: 0o644 });
      await expect(installPreCommitHookDetailed(root)).rejects.toMatchObject({
        code: 'HOOK_HUSKY_DISPATCHER_MISSING'
      });
      expect(existsSync(path.join(root, '.husky', 'pre-commit'))).toBe(false);
    }
  });

  it('warns about other hook managers', async () => {
    const root = makeRepo();
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    mkdirSync(path.dirname(hook), { recursive: true });
    writeFileSync(
      hook,
      '#!/bin/sh\n# generated by lefthook\nlefthook run pre-commit\n',
      { mode: 0o755 }
    );

    const result = await installPreCommitHookDetailed(root);
    expect(result.warnings.join('\n')).toMatch(/lefthook/u);
  }, 30_000);

  it('accepts env-style shell shebangs and keeps the original interpreter line', async () => {
    const root = makeRepo();
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    mkdirSync(path.dirname(hook), { recursive: true });
    for (const shebang of [
      '#!/usr/bin/env sh',
      '#!/usr/bin/env bash',
      '#!/usr/bin/env -S bash -e',
      '#!/bin/bash',
      '#!/bin/dash'
    ]) {
      writeFileSync(hook, `${shebang}\necho user\n`, { mode: 0o755 });
      await installPreCommitHook(root);
      const content = readFileSync(hook, 'utf8');
      expect(content.startsWith(`${shebang}\n`)).toBe(true);
      expect(count(content, BLOCK_START)).toBe(1);
      expect(content).toContain('echo user');
    }
  }, 30_000);

  it('refuses to rewrite a non-shell hook and leaves it untouched', async () => {
    const root = makeRepo();
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    mkdirSync(path.dirname(hook), { recursive: true });
    for (const interpreter of [
      '#!/usr/bin/env python3',
      '#!/usr/bin/env node',
      '#!/usr/bin/perl'
    ]) {
      const body = `${interpreter}\nprint("hi")\n`;
      writeFileSync(hook, body, { mode: 0o755 });
      await expect(installPreCommitHook(root)).rejects.toMatchObject({
        code: 'HOOK_UNSUPPORTED_INTERPRETER'
      });
      expect(readFileSync(hook, 'utf8')).toBe(body);
    }
    const original = '#!/usr/bin/env python3\nprint("hi")\n';
    writeFileSync(hook, original, { mode: 0o755 });

    await expect(installPreCommitHook(root)).rejects.toMatchObject({
      code: 'HOOK_UNSUPPORTED_INTERPRETER'
    });
    expect(readFileSync(hook, 'utf8')).toBe(original);
  }, 30_000);

  it('rejects corrupt or duplicated managed blocks without modifying the file', async () => {
    const root = makeRepo();
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    mkdirSync(path.dirname(hook), { recursive: true });

    for (const broken of [
      `#!/bin/sh\n${BLOCK_START}\nhalf\n`,
      `#!/bin/sh\n${BLOCK_START}\na\n# <<< toolip managed pre-commit <<<\n${BLOCK_START}\nb\n# <<< toolip managed pre-commit <<<\n`
    ]) {
      writeFileSync(hook, broken, { mode: 0o755 });
      await expect(installPreCommitHook(root)).rejects.toMatchObject({
        code: 'HOOK_MANAGED_BLOCK_CORRUPT'
      });
      expect(readFileSync(hook, 'utf8')).toBe(broken);
    }
  });

  it('requires a Git repository', async () => {
    await expect(installPreCommitHook(tempDir())).rejects.toMatchObject({
      code: 'HOOK_GIT_REQUIRED'
    });
  });

  it.skipIf(!posix)(
    'runs offline: prefers the local Toolip, then PATH, and never calls npx',
    async () => {
      const root = makeRepo();
      await installPreCommitHook(root);
      const hook = path.join(root, '.git', 'hooks', 'pre-commit');
      const scratch = tempDir('toolip-bins-');
      const log = path.join(scratch, 'calls.log');

      // npx must never be invoked.
      const bin = stubBin(scratch, 'npx', `echo npx >> "${log}"; exit 99`);
      stubBin(scratch, 'toolip', `echo global >> "${log}"; exit 0`);

      // 1. Local project install wins over PATH.
      const local = path.join(root, 'node_modules', '.bin');
      mkdirSync(local, { recursive: true });
      writeFileSync(
        path.join(local, 'toolip'),
        `#!/bin/sh\necho local >> "${log}"\nexit 0\n`
      );
      chmodSync(path.join(local, 'toolip'), 0o755);
      expect(runHook(hook, root, bin).status).toBe(0);

      // 2. Without it, the PATH Toolip is used.
      write(root, 'node_modules/.bin/toolip', '');
      chmodSync(path.join(local, 'toolip'), 0o644);
      expect(runHook(hook, root, bin).status).toBe(0);

      // 3. With neither, fail closed with remediation and still no npx.
      stubBin(scratch, 'toolip', 'exit 0');
      const empty = path.join(tempDir('toolip-empty-'), 'bin');
      mkdirSync(empty, { recursive: true });
      const missing = runHook(hook, root, empty);
      expect(missing.status).toBe(1);
      expect(missing.stderr).toContain('npm install --save-dev toolip');

      const calls = readFileSync(log, 'utf8').trim().split('\n');
      expect(calls).toEqual(['local', 'global']);
      expect(calls).not.toContain('npx');
    }
  );
});
