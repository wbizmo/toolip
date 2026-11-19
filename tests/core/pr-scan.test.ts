import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  parseChangedLineRanges,
  parseRawChanges,
  scanPullRequestDiff
} from '../../src/core/diff/pr-scan.js';
import {
  parseGitHubPullRequestEvent,
  readGitHubPullRequestEvent
} from '../../src/core/diff/github-pr-event.js';

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
  it('binds a GitHub pull request event to exact base and head commits', async () => {
    const root = await createRepo();
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(path.join(root, 'README.md'), 'review change\n');
    git(root, 'add', 'README.md');
    git(root, 'commit', '-qm', 'review change');
    const head = git(root, 'rev-parse', 'HEAD');
    const eventPath = path.join(root, 'event.json');
    await writeFile(
      eventPath,
      JSON.stringify({
        action: 'synchronize',
        repository: { id: 1234, full_name: 'acme/toolip' },
        pull_request: {
          number: 42,
          base: {
            sha: base,
            repo: { id: 1234, full_name: 'acme/toolip' }
          },
          head: {
            sha: head,
            repo: { id: 5678, full_name: 'contributor/toolip' }
          }
        }
      })
    );

    const context = await readGitHubPullRequestEvent(eventPath, 'acme/toolip');
    expect(context).toEqual({
      action: 'synchronize',
      repository: 'acme/toolip',
      pullRequestNumber: 42,
      baseSha: base,
      headSha: head,
      headRepository: 'contributor/toolip'
    });

    const result = await scanPullRequestDiff(
      root,
      context.baseSha,
      context.headSha
    );
    expect(result.baseCommit).toBe(base);
    expect(result.headCommit).toBe(head);
  });

  it('rejects malformed, duplicate-key, stale-action and cross-repository events', () => {
    const valid = {
      action: 'opened',
      repository: { id: 1234, full_name: 'acme/toolip' },
      pull_request: {
        number: 42,
        base: {
          sha: 'a'.repeat(40),
          repo: { id: 1234, full_name: 'acme/toolip' }
        },
        head: {
          sha: 'b'.repeat(40),
          repo: { id: 5678, full_name: 'contributor/toolip' }
        }
      }
    };
    expect(() =>
      parseGitHubPullRequestEvent(
        JSON.stringify({ ...valid, action: 'closed' }),
        'acme/toolip'
      )
    ).toThrow(expect.objectContaining({ code: 'GITHUB_EVENT_INVALID' }));
    expect(() =>
      parseGitHubPullRequestEvent(
        JSON.stringify({
          ...valid,
          pull_request: {
            ...valid.pull_request,
            base: {
              ...valid.pull_request.base,
              repo: { id: 9999, full_name: 'other/repo' }
            }
          }
        }),
        'acme/toolip'
      )
    ).toThrow(expect.objectContaining({ code: 'GITHUB_EVENT_INVALID' }));
    expect(() =>
      parseGitHubPullRequestEvent(
        JSON.stringify({
          ...valid,
          pull_request: { ...valid.pull_request, head: null }
        }),
        'acme/toolip'
      )
    ).toThrow(expect.objectContaining({ code: 'GITHUB_EVENT_INVALID' }));
    expect(() =>
      parseGitHubPullRequestEvent(
        '{"action":"opened","action":"synchronize"}',
        'acme/toolip'
      )
    ).toThrow(expect.objectContaining({ code: 'GITHUB_EVENT_INVALID' }));
    expect(() =>
      parseGitHubPullRequestEvent(JSON.stringify(valid), 'other/repo')
    ).toThrow(expect.objectContaining({ code: 'GITHUB_EVENT_INVALID' }));
  });

  it('rejects oversized and symlinked GitHub event files', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pr-event-file-'));
    roots.push(root);
    const oversized = path.join(root, 'oversized.json');
    await writeFile(oversized, Buffer.alloc(1024 * 1024 + 1));
    await expect(
      readGitHubPullRequestEvent(oversized, 'acme/toolip')
    ).rejects.toMatchObject({ code: 'GITHUB_EVENT_INVALID' });

    if (process.platform !== 'win32') {
      const target = path.join(root, 'target.json');
      const link = path.join(root, 'event.json');
      await writeFile(target, '{}');
      await symlink(target, link);
      await expect(
        readGitHubPullRequestEvent(link, 'acme/toolip')
      ).rejects.toMatchObject({ code: 'GITHUB_EVENT_INVALID' });
    }
  });

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

  it('uses the committed head blob when the worktree has different bytes', async () => {
    const root = await createRepo();
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'src/app.ts'),
      `const token = "${fakeGithubToken}";\n`
    );
    git(root, 'add', 'src/app.ts');
    git(root, 'commit', '-qm', 'commit credential');
    const head = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'src/app.ts'),
      'export const clean = true;\n'
    );

    const result = await scanPullRequestDiff(root, base, head);
    expect(result.headCommit).toBe(head);
    expect(result.introduced).toMatchObject([
      { ruleId: 'TOOLIP-SECRET-GITHUB-TOKEN', location: { line: 1 } }
    ]);
    expect(JSON.stringify(result)).not.toContain(fakeGithubToken);
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

  it('treats a copied source file as a new changed path', async () => {
    const root = await createRepo();
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'src/copied.ts'),
      `const token = "${fakeGithubToken}";\n`
    );
    git(root, 'add', 'src/copied.ts');
    git(root, 'commit', '-qm', 'copy source with credential');

    const result = await scanPullRequestDiff(root, base, 'HEAD');
    expect(result.changedFiles).toEqual([
      expect.objectContaining({ status: 'A', newPath: 'src/copied.ts' })
    ]);
    expect(result.introduced).toMatchObject([
      {
        ruleId: 'TOOLIP-SECRET-GITHUB-TOKEN',
        location: { file: 'src/copied.ts' }
      }
    ]);
    expect(result.coverage).toBe('incomplete');
  });

  it('matches repeated findings in a long line without changing their impact', async () => {
    const root = await createRepo();
    const repeatedSecrets = Array.from({ length: 9 }, (_, index) =>
      ['ghp_', String(index + 1).repeat(36)].join('')
    ).join(' ');
    const secretLine = `${repeatedSecrets} ${'x'.repeat(256 * 1024)}`;
    await writeFile(
      path.join(root, 'credentials.env'),
      `${secretLine}\nstable context\nstable context\nbefore\n`
    );
    git(root, 'add', 'credentials.env');
    git(root, 'commit', '-qm', 'add repeated synthetic findings');
    const base = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'credentials.env'),
      `${secretLine}\nstable context\nstable context\nafter\n`
    );
    git(root, 'add', 'credentials.env');
    git(root, 'commit', '-qm', 'change an unrelated line');

    const result = await scanPullRequestDiff(root, base, 'HEAD');
    expect(result.unchangedCount).toBeGreaterThan(1);
    expect(result.introduced).toEqual([]);
    expect(result.fixed).toEqual([]);
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
      'dependency-license-impact-not-recomputed'
    );
    expect(result.reasons).toContain(
      'dependency-reachability-impact-not-recomputed'
    );
    expect(result.reasons).toContain(
      'dependency-provenance-impact-not-recomputed'
    );
    expect(result.reasons).toContain(
      'dependency-maintainer-impact-not-recomputed'
    );
    expect(result.reasons).toContain('dependency-policy-impact-not-recomputed');
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

  it('keeps removed and renamed analyzer inputs explicitly incomplete', async () => {
    const root = await createRepo();
    await mkdir(path.join(root, '.vscode'), { recursive: true });
    await mkdir(path.join(root, '.toolip'), { recursive: true });
    await writeFile(
      path.join(root, '.vscode/tasks.json'),
      JSON.stringify({ version: '2.0.0', tasks: [] })
    );
    await writeFile(path.join(root, '.toolip/policy.yaml'), 'version: 1\n');
    await writeFile(path.join(root, 'Dockerfile'), 'FROM scratch\n');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'add task, policy and container');
    const base = git(root, 'rev-parse', 'HEAD');

    git(root, 'mv', 'src/app.ts', 'src/app.bin');
    git(root, 'rm', '.vscode/tasks.json', '.toolip/policy.yaml', 'Dockerfile');
    git(root, 'commit', '-qm', 'remove and rename analyzed inputs');

    const result = await scanPullRequestDiff(root, base, 'HEAD');
    expect(result.reasons).toContain(
      'malicious-execution-graph-analysis-not-run'
    );
    expect(result.reasons).toContain('infrastructure-analysis-not-run');
    expect(result.reasons).toContain('policy-effects-not-recomputed');
    expect(result.reasons).toContain(
      'specialized-analysis-not-run:src/app.bin'
    );
    expect(result.coverage).toBe('incomplete');
    expect(result.analysisState).toBe('failed');
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

  it('reports an exact version change in a transitive dependency instance', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pr-transitive-'));
    roots.push(root);
    execFileSync('git', ['init', '-q', root]);
    git(root, 'config', 'user.name', 'Toolip Test');
    git(root, 'config', 'user.email', 'test@example.invalid');
    const writeGraph = async (transitiveVersion: string): Promise<void> => {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ name: 'fixture', dependencies: { alpha: '^1.0.0' } })
      );
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          name: 'fixture',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { alpha: '^1.0.0' } },
            'node_modules/alpha': {
              name: 'alpha',
              version: '1.0.0',
              resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz',
              dependencies: { beta: '^1.0.0' }
            },
            'node_modules/alpha/node_modules/beta': {
              name: 'beta',
              version: transitiveVersion,
              resolved: `https://registry.npmjs.org/beta/-/beta-${transitiveVersion}.tgz`
            }
          }
        })
      );
    };
    await writeGraph('1.0.0');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'base transitive lock graph');
    const base = git(root, 'rev-parse', 'HEAD');
    await writeGraph('1.1.0');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'update transitive package');

    const result = await scanPullRequestDiff(root, base, 'HEAD');
    expect(result.dependencyImpact).toMatchObject({
      state: 'complete',
      versionChangedCount: 1,
      versionChanged: [
        {
          before: {
            ecosystem: 'npm',
            name: 'beta',
            version: '1.0.0',
            installPath: 'node_modules/alpha/node_modules/beta'
          },
          after: {
            ecosystem: 'npm',
            name: 'beta',
            version: '1.1.0',
            installPath: 'node_modules/alpha/node_modules/beta'
          }
        }
      ]
    });
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
