import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createProgram } from '../../src/cli/program.js';

const roots: string[] = [];
const fakeGithubToken = ['ghp_', '123456789012345678901234567890'].join('');

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

describe('pr-scan GitHub event adapter', () => {
  it('scans exact event SHAs and emits bounded PR context without remote writes', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pr-event-cli-'));
    roots.push(root);
    execFileSync('git', ['init', '-q', root]);
    git(root, 'config', 'user.name', 'Toolip Test');
    git(root, 'config', 'user.email', 'test@example.invalid');
    await writeFile(path.join(root, 'README.md'), 'before\n');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'base');
    const baseSha = git(root, 'rev-parse', 'HEAD');
    await writeFile(path.join(root, 'README.md'), 'after\n');
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'head');
    const headSha = git(root, 'rev-parse', 'HEAD');
    const eventPath = path.join(root, 'event.json');
    await writeFile(
      eventPath,
      JSON.stringify({
        action: 'synchronize',
        repository: { id: 1234, full_name: 'acme/toolip' },
        pull_request: {
          number: 42,
          base: {
            sha: baseSha,
            repo: { id: 1234, full_name: 'acme/toolip' }
          },
          head: {
            sha: headSha,
            repo: { id: 5678, full_name: 'contributor/toolip' }
          }
        }
      })
    );
    const output: string[] = [];
    const write = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk) => {
        output.push(String(chunk));
        return true;
      });
    const previousExitCode = process.exitCode;
    try {
      await createProgram().parseAsync(
        [
          'pr-scan',
          '--github-event',
          eventPath,
          '--github-repository',
          'acme/toolip',
          '--path',
          root,
          '--json',
          '--fail-on',
          'none'
        ],
        { from: 'user' }
      );
      const result = JSON.parse(output.join('')) as {
        baseCommit: string;
        headCommit: string;
        githubPullRequest: {
          repository: string;
          number: number;
          headRepository: string;
        };
      };
      expect(result.baseCommit).toBe(baseSha);
      expect(result.headCommit).toBe(headSha);
      expect(result.githubPullRequest).toEqual({
        repository: 'acme/toolip',
        number: 42,
        headRepository: 'contributor/toolip'
      });
    } finally {
      process.exitCode = previousExitCode;
      write.mockRestore();
    }
  });

  it('rejects mixing explicit refs with event metadata or omitting its repository binding', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-pr-event-args-'));
    roots.push(root);
    await expect(
      createProgram().parseAsync(
        [
          'pr-scan',
          'HEAD',
          '--github-event',
          path.join(root, 'unused.json'),
          '--github-repository',
          'acme/toolip'
        ],
        { from: 'user' }
      )
    ).rejects.toMatchObject({ code: 'PR_SCAN_INPUT_INVALID' });
    await expect(
      createProgram().parseAsync(
        ['pr-scan', '--github-event', path.join(root, 'unused.json')],
        { from: 'user' }
      )
    ).rejects.toMatchObject({ code: 'PR_SCAN_INPUT_INVALID' });
  });

  it('writes SARIF annotations at exact introduced changed lines', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-pr-event-sarif-')
    );
    roots.push(root);
    execFileSync('git', ['init', '-q', root]);
    git(root, 'config', 'user.name', 'Toolip Test');
    git(root, 'config', 'user.email', 'test@example.invalid');
    await mkdir(path.join(root, 'src'), { recursive: true });
    await writeFile(
      path.join(root, 'src/app.ts'),
      'export const ready = true;\nexport const token = "safe";\n'
    );
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'base');
    const baseSha = git(root, 'rev-parse', 'HEAD');
    await writeFile(
      path.join(root, 'src/app.ts'),
      `export const ready = true;\nexport const token = "${fakeGithubToken}";\n`
    );
    git(root, 'add', '--all');
    git(root, 'commit', '-qm', 'introduce credential');
    const headSha = git(root, 'rev-parse', 'HEAD');
    const eventPath = path.join(root, 'event.json');
    const sarifPath = path.join(root, 'report.sarif');
    await writeFile(
      eventPath,
      JSON.stringify({
        action: 'synchronize',
        repository: { id: 1234, full_name: 'acme/toolip' },
        pull_request: {
          number: 42,
          base: { sha: baseSha, repo: { id: 1234, full_name: 'acme/toolip' } },
          head: {
            sha: headSha,
            repo: { id: 5678, full_name: 'contributor/toolip' }
          }
        }
      })
    );
    const previousExitCode = process.exitCode;
    const stdoutWrite = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation(() => true);
    try {
      await createProgram().parseAsync(
        [
          'pr-scan',
          '--github-event',
          eventPath,
          '--github-repository',
          'acme/toolip',
          '--path',
          root,
          '--sarif',
          sarifPath,
          '--json',
          '--fail-on',
          'none'
        ],
        { from: 'user' }
      );
      const sarif = JSON.parse(await readFile(sarifPath, 'utf8')) as {
        runs: Array<{
          results: Array<{
            locations: Array<{
              physicalLocation: {
                artifactLocation: { uri: string };
                region: { startLine: number };
              };
            }>;
          }>;
          invocations: Array<{ executionSuccessful: boolean }>;
        }>;
      };
      expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation).toEqual(
        {
          artifactLocation: { uri: 'src/app.ts' },
          region: { startLine: 2, startColumn: 23 }
        }
      );
      expect(sarif.runs[0]?.invocations[0]?.executionSuccessful).toBe(false);
      expect(JSON.stringify(sarif)).not.toContain(fakeGithubToken);
    } finally {
      stdoutWrite.mockRestore();
      process.exitCode = previousExitCode;
    }
  });
});
