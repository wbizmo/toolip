import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  parseChangedLineRanges,
  parseRawChanges,
  scanPullRequestDiff
} from '../../src/core/diff/pr-scan.js';

const roots: string[] = [];
const fakeGithubToken = ['ghp_', '123456789012345678901234567890'].join('');
const oid = 'a'.repeat(40);

afterEach(async () =>
  Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  )
);

function git(root: string, ...args: string[]): string {
  return execFileSync(
    'git',
    ['-C', root, '-c', 'core.hooksPath=/dev/null', ...args],
    { encoding: 'utf8' }
  ).trim();
}

async function createRepo(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pr-scan-'));
  roots.push(root);
  execFileSync('git', ['init', '-q', root]);
  git(root, 'config', 'user.name', 'Toolip Test');
  git(root, 'config', 'user.email', 'test@example.invalid');
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'src/app.ts'), 'export const ok = true;\n');
  git(root, 'add', '--all');
  git(root, 'commit', '-qm', 'base');
  return root;
}

describe('pull request changed-file security scan', () => {
  it('parses NUL-delimited rename metadata without losing spaces in paths', () => {
    const raw = Buffer.from(
      `:100644 100644 ${oid} ${'b'.repeat(40)} R098\0old name.ts\0new name.ts\0`,
      'utf8'
    );
    expect(parseRawChanges(raw)).toEqual([
      {
        status: 'R098',
        oldPath: 'old name.ts',
        newPath: 'new name.ts',
        oldOid: oid,
        newOid: 'b'.repeat(40),
        oldMode: '100644',
        newMode: '100644'
      }
    ]);
  });

  it('rejects truncated or malformed Git metadata and ambiguous quoted paths', () => {
    expect(() => parseRawChanges(Buffer.from(':malformed\0file.ts\0'))).toThrow(
      'metadata is malformed'
    );
    expect(() =>
      parseRawChanges(Buffer.from(`:100644 100644 ${oid} ${oid} M\0file.ts`))
    ).toThrow('truncated');
    expect(() =>
      parseChangedLineRanges(
        Buffer.from('+++ "b/file\\nname.ts"\n@@ -1 +1 @@\n')
      )
    ).toThrow('Quoted Git paths');
  });

  it('maps zero-context hunks to exact head-side line intervals', () => {
    expect(
      parseChangedLineRanges(
        Buffer.from(
          'diff --git a/src/app.ts b/src/app.ts\n+++ b/src/app.ts\n@@ -4,2 +5,3 @@\n'
        )
      )
    ).toEqual({ 'src/app.ts': [{ start: 5, end: 7 }] });
  });

  it('resolves exact commits, reports introduced secrets, and marks unsupported graph analysis incomplete', async () => {
    const root = await createRepo();
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'src/app.ts'),
      `export const ok = true;\nconst token = "${fakeGithubToken}";\n`
    );
    git(root, 'add', 'src/app.ts');
    git(root, 'commit', '-qm', 'add credential');
    const head = git(root, 'rev-parse', 'HEAD');

    const result = await scanPullRequestDiff(root, base, head);

    expect(result).toMatchObject({
      baseCommit: base,
      headCommit: head,
      coverage: 'incomplete',
      analysisState: 'failed',
      changedFiles: [{ status: 'M', newPath: 'src/app.ts' }],
      changedLineRanges: { 'src/app.ts': [{ start: 2, end: 2 }] },
      introduced: [
        { ruleId: 'TOOLIP-SECRET-GITHUB-TOKEN', location: { line: 2 } }
      ]
    });
    expect(JSON.stringify(result)).not.toContain(
      'ghp_123456789012345678901234567890'
    );
    expect(result.reasons).toContain(
      'malicious-execution-graph-analysis-not-run'
    );
    expect(result.inlineReviewComments).toHaveLength(1);
    expect(result.inlineReviewComments[0]).toMatchObject({
      path: 'src/app.ts',
      line: 2,
      severity: 'critical'
    });
    expect(result.inlineReviewComments[0]?.body).not.toContain(fakeGithubToken);
    expect(result.inlineReviewComments[0]?.body).not.toContain('token =');
    expect(result.inlineReviewCommentsTruncated).toBe(false);
  });

  it('keeps an unchanged finding stable across an exact Git rename', async () => {
    const root = await createRepo();
    await writeFile(
      path.join(root, 'src/app.ts'),
      `export const token = "${fakeGithubToken}";\n`
    );
    git(root, 'add', 'src/app.ts');
    git(root, 'commit', '-qm', 'baseline secret');
    const base = git(root, 'rev-parse', 'HEAD');
    git(root, 'mv', 'src/app.ts', 'src/renamed.ts');
    git(root, 'commit', '-qm', 'rename secret file');

    const result = await scanPullRequestDiff(root, base, 'HEAD');

    expect(result.changedFiles).toEqual([
      expect.objectContaining({
        status: 'R100',
        oldPath: 'src/app.ts',
        newPath: 'src/renamed.ts'
      })
    ]);
    expect(result.introduced).toEqual([]);
    expect(result.fixed).toEqual([]);
    expect(result.unchangedCount).toBe(1);
  });

  it('marks dependency graph, symlink and unsupported file changes incomplete', async () => {
    const root = await createRepo();
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(path.join(root, 'package-lock.json'), '{}\n');
    await writeFile(path.join(root, 'release.bin'), Buffer.from([0, 1, 2]));
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'change dependency and binary');

    const result = await scanPullRequestDiff(root, base, 'HEAD');

    expect(result.coverage).toBe('incomplete');
    expect(result.analysisState).toBe('failed');
    expect(result.reasons).toContain(
      'dependency-graph-change-requires-full-scan'
    );
    expect(result.reasons).toContain(
      'specialized-analysis-not-run:release.bin'
    );
    expect(result.reasons).toContain('binary-change-requires-review');
  });

  it('does not report Docker or IaC changes as fully scanned by the diff-only path', async () => {
    const root = await createRepo();
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'Dockerfile'),
      'FROM alpine:latest\nUSER root\n'
    );
    await writeFile(path.join(root, 'infra.tf'), 'resource "x" "y" {}\n');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'add infrastructure');

    const result = await scanPullRequestDiff(root, base, 'HEAD');
    expect(result.coverage).toBe('incomplete');
    expect(result.reasons).toContain('infrastructure-analysis-not-run');
  });

  it('compares resolved dependency instances from exact base and head lockfile blobs', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pr-deps-'));
    roots.push(root);
    execFileSync('git', ['init', '-q', root]);
    git(root, 'config', 'user.name', 'Toolip Test');
    git(root, 'config', 'user.email', 'test@example.invalid');
    const writeNpmGraph = async (version: string): Promise<void> => {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'fixture',
          version: '1.0.0',
          dependencies: { alpha: '^1.0.0' }
        })
      );
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          name: 'fixture',
          version: '1.0.0',
          lockfileVersion: 3,
          requires: true,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: { alpha: '^1.0.0' }
            },
            'node_modules/alpha': {
              name: 'alpha',
              version,
              resolved: `https://registry.npmjs.org/alpha/-/alpha-${version}.tgz`
            }
          }
        })
      );
    };
    await writeNpmGraph('1.0.0');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'base lock graph');
    const base = git(root, 'rev-parse', 'HEAD');
    await writeNpmGraph('1.1.0');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'upgrade dependency');
    const head = git(root, 'rev-parse', 'HEAD');

    const queries: string[] = [];
    const onlineResult = await scanPullRequestDiff(
      root,
      base,
      head,
      undefined,
      {
        onlineAdvisories: true,
        advisoryClient: {
          async queryBatch(requests) {
            queries.push(
              ...requests.map(
                (request) => `${request.package.name}@${request.version}`
              )
            );
            return requests.map((query) => ({
              query,
              vulnerabilities:
                query.version === '1.0.0'
                  ? [
                      {
                        id: 'GHSA-old',
                        aliases: ['CVE-2024-1234', 'GHSA-alias']
                      }
                    ]
                  : []
            }));
          }
        }
      }
    );
    const unavailableResult = await scanPullRequestDiff(
      root,
      base,
      head,
      undefined,
      {
        onlineAdvisories: true,
        advisoryClient: {
          async queryBatch() {
            throw new Error('provider response may contain request details');
          }
        }
      }
    );
    const result = await scanPullRequestDiff(root, base, head);

    expect(result.dependencyImpact).toMatchObject({
      state: 'complete',
      basePackageCount: 1,
      headPackageCount: 1,
      addedCount: 0,
      removedCount: 0,
      versionChangedCount: 1,
      versionChanged: [
        {
          before: { ecosystem: 'npm', name: 'alpha', version: '1.0.0' },
          after: { ecosystem: 'npm', name: 'alpha', version: '1.1.0' }
        }
      ],
      advisoryStatus: 'not-recomputed'
    });
    expect(queries.sort()).toEqual(['alpha@1.0.0', 'alpha@1.1.0']);
    expect(onlineResult.dependencyImpact).toMatchObject({
      advisoryStatus: 'complete',
      introducedAdvisories: [],
      fixedAdvisories: [
        {
          ecosystem: 'npm',
          name: 'alpha',
          version: '1.0.0',
          installPath: 'node_modules/alpha',
          advisoryId: 'CVE-2024-1234',
          aliases: ['CVE-2024-1234', 'GHSA-ALIAS', 'GHSA-OLD']
        }
      ]
    });
    expect(unavailableResult.dependencyImpact).toMatchObject({
      advisoryStatus: 'incomplete',
      introducedAdvisories: [],
      fixedAdvisories: [],
      warnings: ['advisory-provider-unavailable']
    });
    expect(unavailableResult.reasons).toContain(
      'dependency-advisory-impact-incomplete'
    );
    expect(JSON.stringify(unavailableResult)).not.toContain(
      'provider response may contain request details'
    );
    expect(result.coverage).toBe('incomplete');
    expect(result.reasons).toContain(
      'dependency-advisory-impact-not-recomputed'
    );
  });

  it('marks non-npm ecosystem manifest changes as unresolved dependency impact', async () => {
    const root = await createRepo();
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'requirements-dev.txt'),
      'example-package>=1.2\n'
    );
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'change Python dependency declaration');

    const result = await scanPullRequestDiff(root, base, 'HEAD');
    expect(result.coverage).toBe('incomplete');
    expect(result.reasons).toContain(
      'dependency-graph-change-requires-full-scan'
    );
  });

  it('withholds scoped npm advisory queries without explicit public-scope consent', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pr-private-'));
    roots.push(root);
    execFileSync('git', ['init', '-q', root]);
    git(root, 'config', 'user.name', 'Toolip Test');
    git(root, 'config', 'user.email', 'test@example.invalid');
    const writeGraph = async (version: string): Promise<void> => {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'fixture',
          dependencies: { '@private/alpha': '^1.0.0' }
        })
      );
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              dependencies: { '@private/alpha': '^1.0.0' }
            },
            'node_modules/@private/alpha': {
              name: '@private/alpha',
              version,
              resolved: `https://registry.npmjs.org/@private/alpha/-/alpha-${version}.tgz`
            }
          }
        })
      );
    };
    await writeGraph('1.0.0');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'base private lock graph');
    const base = git(root, 'rev-parse', 'HEAD');
    await writeGraph('1.1.0');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'update private dependency');
    let calls = 0;
    const result = await scanPullRequestDiff(root, base, 'HEAD', undefined, {
      onlineAdvisories: true,
      advisoryClient: {
        async queryBatch() {
          calls++;
          return [];
        }
      }
    });

    expect(calls).toBe(0);
    expect(result.dependencyImpact).toMatchObject({
      advisoryStatus: 'incomplete',
      warnings: ['advisory-scoped-npm-query-withheld'],
      introducedAdvisories: [],
      fixedAdvisories: []
    });
  });

  it('rejects option-like revisions and honors cancellation', async () => {
    const root = await createRepo();
    await expect(
      scanPullRequestDiff(root, '--output=unsafe')
    ).rejects.toMatchObject({
      code: 'GIT_REVISION_INVALID'
    });
    const controller = new AbortController();
    controller.abort();
    await expect(
      scanPullRequestDiff(root, 'HEAD', 'HEAD', controller.signal)
    ).rejects.toThrow();
  });
});
