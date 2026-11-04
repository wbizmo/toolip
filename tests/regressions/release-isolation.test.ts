import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const script = path.resolve('scripts/verify-workflows.mjs');
const dirs: string[] = [];

function run(workflows: Record<string, string>) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-wf-'));
  dirs.push(dir);
  for (const [name, body] of Object.entries(workflows)) {
    writeFileSync(path.join(dir, name), body);
  }
  return spawnSync(process.execPath, [script], {
    encoding: 'utf8',
    env: { ...process.env, WORKFLOWS_DIR: dir }
  });
}

const SHA = 'a'.repeat(40);
const safe = (on: string, extra = '') => `name: x
on: ${on}
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@${SHA}
${extra}`;

afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe('release isolation policy (regression for Batch 00)', () => {
  it('accepts the repository workflows', () => {
    const result = spawnSync(process.execPath, [script], { encoding: 'utf8' });
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
  });

  it('rejects a release workflow triggered by push', () => {
    const result = run({
      'publish.yml': safe('{ push: { branches: [main] } }')
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('workflow_dispatch only');
  });

  it('rejects publish commands outside release workflows', () => {
    const result = run({
      'ci.yml': safe('{ pull_request: {} }', '      - run: npm publish\n')
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('publish/release');
  });

  it('rejects pull_request_target and unpinned actions', () => {
    const result = run({
      'ci.yml': safe('{ pull_request_target: {} }').replace(SHA, 'v4')
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('pull_request_target');
    expect(result.stderr).toContain('not pinned');
  });

  it('rejects top-level write permissions', () => {
    const result = run({
      'ci.yml': safe('{ pull_request: {} }').replace(
        'contents: read',
        'contents: write'
      )
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('top-level write permission');
  });

  it('rejects npm ci without --ignore-scripts', () => {
    const result = run({
      'ci.yml': safe('{ pull_request: {} }', '      - run: npm ci\n')
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('--ignore-scripts');
    expect(
      run({
        'ci.yml': safe(
          '{ pull_request: {} }',
          '      - run: npm ci --ignore-scripts\n'
        )
      }).status
    ).toBe(0);
  });

  it('runs CodeQL from one workflow for PRs, main and the schedule', () => {
    const doc = parse(readFileSync('.github/workflows/codeql.yml', 'utf8'));
    expect(Object.keys(doc.on).sort()).toEqual([
      'pull_request',
      'push',
      'schedule'
    ]);
    expect(Object.keys(doc.jobs)).toEqual(['analyze']);
    expect(
      readFileSync('.github/workflows/pr-quality.yml', 'utf8')
    ).not.toMatch(/codeql-action/);
  });
});
