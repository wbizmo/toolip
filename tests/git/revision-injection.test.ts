import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { securityDiff } from '../../src/core/diff/security-diff.js';
import { isSafeRevisionSyntax } from '../../src/core/git/revision.js';
import {
  cleanupRepos,
  git,
  makeRepo,
  tempDir,
  write
} from '../helpers/git-repo.js';

afterEach(cleanupRepos);

// Issue #45: `${base}..${head}` was one git argument, so a value beginning with
// `-` such as `--output=/path` was parsed as an option and wrote a file.
describe('Git revision option injection (issue #45)', () => {
  it('rejects option-like and expression-like revisions without side effects', async () => {
    const root = makeRepo();
    const outside = tempDir('toolip-canary-');
    const canary = path.join(outside, 'canary.txt');

    const hostile = [
      `--output=${canary}`,
      `--output=${canary}..HEAD`,
      '--output=PWNED',
      '-p',
      '--no-index',
      '--stat',
      '--exec=touch PWNED',
      '--upload-pack=touch PWNED',
      '-',
      '',
      'a\0b',
      'a\nb',
      'a b',
      '\tmain',
      'HEAD..HEAD',
      'HEAD...main',
      'HEAD~1',
      'HEAD^',
      'main:README.md',
      '@{u}',
      '..',
      'a//b',
      '.hidden',
      'main/',
      'x'.repeat(500)
    ];

    for (const value of hostile) {
      await expect(securityDiff(root, value, 'HEAD')).rejects.toMatchObject({
        code: 'GIT_REVISION_INVALID'
      });
      await expect(securityDiff(root, 'HEAD', value)).rejects.toMatchObject({
        code: 'GIT_REVISION_INVALID'
      });
    }

    expect(existsSync(canary)).toBe(false);
    expect(existsSync(path.join(root, 'PWNED'))).toBe(false);
    expect(readdirSync(outside)).toEqual([]);
    expect(git(root, 'status', '--porcelain')).toBe('');
  });

  it('accepts branches, tags, HEAD and full or short commit IDs', async () => {
    const root = makeRepo();
    const base = git(root, 'rev-parse', 'HEAD').trim();
    git(root, 'tag', 'v1.0.0');
    git(root, 'checkout', '-q', '-b', 'feature/new-thing');
    write(root, 'package.json', '{}');
    write(root, 'src/app.ts', 'export {};\n');
    git(root, 'add', '.');
    git(root, 'commit', '-q', '-m', 'change');
    const head = git(root, 'rev-parse', 'HEAD').trim();

    for (const [b, h] of [
      ['v1.0.0', 'feature/new-thing'],
      [base, head],
      [base.slice(0, 10), head.slice(0, 10)],
      ['main', 'HEAD']
    ] as const) {
      const result = await securityDiff(root, b, h);
      expect(result.baseCommit).toBe(base);
      expect(result.headCommit).toBe(head);
      expect(result.files.sort()).toEqual(['package.json', 'src/app.ts']);
      expect(result.packageManifestChanged).toBe(true);
      expect(result.sourceFilesChanged).toEqual(['src/app.ts']);
    }
  });

  it('works on a detached HEAD and in a linked worktree', async () => {
    const root = makeRepo();
    const first = git(root, 'rev-parse', 'HEAD').trim();
    write(root, 'a.ts', 'export {};\n');
    git(root, 'add', '.');
    git(root, 'commit', '-q', '-m', 'second');
    git(root, 'checkout', '-q', '--detach', 'HEAD');

    expect((await securityDiff(root, first, 'HEAD')).files).toEqual(['a.ts']);

    const worktree = path.join(tempDir('toolip-wt-'), 'wt');
    git(root, 'worktree', 'add', '-q', worktree, 'main');
    expect((await securityDiff(worktree, first, 'main')).files).toEqual([
      'a.ts'
    ]);
  }, 30_000);

  it('reports unknown revisions with a typed error that leaks no paths', async () => {
    const root = makeRepo();
    const error = await securityDiff(root, 'no-such-ref', 'HEAD').catch(
      (e) => e
    );
    expect(error.code).toBe('GIT_REVISION_NOT_FOUND');
    expect(error.message).not.toContain(root);
  });

  it('handles file names with spaces, newlines and non-ASCII characters', async () => {
    const root = makeRepo();
    const base = git(root, 'rev-parse', 'HEAD').trim();
    const names = ['with space.ts', 'ünï-cødé.ts', 'dir/inner name.json'];
    for (const name of names) write(root, name, 'x');
    if (process.platform !== 'win32') {
      writeFileSync(path.join(root, 'new\nline.ts'), 'x');
      names.push('new\nline.ts');
    }
    git(root, 'add', '.');
    git(root, 'commit', '-q', '-m', 'odd names');

    const result = await securityDiff(root, base, 'HEAD');
    expect(result.files.sort()).toEqual([...names].sort());
  });

  it('keeps the syntax check strict and total', () => {
    for (const ok of [
      'HEAD',
      'main',
      'v1.2.3',
      'release/2026-11',
      'a'.repeat(40),
      'user@host'
    ]) {
      expect(isSafeRevisionSyntax(ok)).toBe(true);
    }
    for (const bad of [
      undefined,
      null,
      5,
      {},
      '-a',
      'a..b',
      'a.lock',
      'a.',
      '--'
    ]) {
      expect(isSafeRevisionSyntax(bad)).toBe(false);
    }
  });
});
