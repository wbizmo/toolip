import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
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
    const stageA = parse(readFileSync('.github/workflows/stage-a.yml', 'utf8'));
    const trustedRuntime = stageA.jobs.scan.steps.find((step) =>
      step.uses.startsWith('actions/setup-node@')
    );
    expect(trustedRuntime.with).toMatchObject({
      'node-version': '24.22.1',
      'check-latest': false
    });
  });

  it('gates pull request installation and execution behind exact-tree Stage A approval', () => {
    const stageA = parse(readFileSync('.github/workflows/stage-a.yml', 'utf8'));
    const stageASteps = stageA.jobs.scan.steps;
    const trustedCheckout = stageASteps.find((step) =>
      step.uses?.startsWith('actions/checkout@')
    );
    const scannerIndex = stageASteps.findIndex((step) =>
      String(step.run ?? '').includes('scripts/stage-a-gate.mjs')
    );
    const installs = stageASteps.flatMap((step, index) =>
      /\bnpm\s+ci\b/u.test(String(step.run ?? '')) ? [index] : []
    );
    const installIndex = installs[0] ?? -1;
    const artifactIndex = stageASteps.findIndex((step) =>
      String(step.run ?? '').includes('scripts/write-stage-a-artifact.mjs')
    );

    expect(Object.keys(stageA.on)).toEqual(['pull_request_target']);
    expect(stageA.on.pull_request_target.types).toContain('edited');
    expect(stageA.permissions).toEqual({
      contents: 'read',
      'pull-requests': 'read'
    });
    expect(trustedCheckout?.with).toMatchObject({
      ref: ['${{', ' github.event.pull_request.base.sha }}'].join(''),
      'persist-credentials': false
    });
    expect(scannerIndex).toBeGreaterThan(0);
    expect(installs).toHaveLength(1);
    expect(installIndex).toBeGreaterThan(scannerIndex);
    expect(artifactIndex).toBeGreaterThan(installIndex);
    expect(stageASteps[installIndex]?.if).toContain(
      "steps.gate.outputs.status == 'approved'"
    );
    expect(stageASteps[installIndex]?.run).toContain('npm ci --ignore-scripts');

    for (const file of ['ci.yml', 'pr-quality.yml', 'codeql.yml']) {
      const stageB = parse(
        readFileSync(path.join('.github/workflows', file), 'utf8')
      );
      expect(stageB.on.workflow_run).toMatchObject({
        workflows: ['Stage A Trusted Pre-execution Gate'],
        branches: ['main']
      });
      expect(
        stageB.jobs['stage-a-result'].steps.some((step) =>
          String(step.run ?? '').includes('verify-stage-a-artifact.mjs')
        )
      ).toBe(true);
      expect(stageB.jobs['stage-a-result'].if).toContain(
        "github.event_name == 'workflow_run'"
      );
      expect(
        stageB.jobs['stage-a-result'].steps.some(
          (step) =>
            String(step.if ?? '').includes(
              "github.event.workflow_run.conclusion != 'success'"
            ) && String(step.run ?? '').includes('exit 1')
        )
      ).toBe(true);
      expect(stageB.permissions['pull-requests']).toBe('read');
      expect(
        stageB.jobs['stage-a-result'].steps.find((step) =>
          String(step.run ?? '').includes('verify-stage-a-artifact.mjs')
        )?.env?.GITHUB_TOKEN
      ).toEqual(['${{', ' github.token }}'].join(''));
      for (const [name, job] of Object.entries(stageB.jobs)) {
        if (
          name !== 'stage-a-result' &&
          (job.steps ?? []).some(
            (step) => step.run || step.uses?.startsWith('actions/checkout@')
          )
        ) {
          expect(job.needs).toContain('stage-a-result');
        }
      }
    }
  });

  it('assigns pre-execution trust roots to the repository owner', () => {
    const entries = readFileSync('.github/CODEOWNERS', 'utf8')
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
    for (const pattern of [
      '/.github/workflows/',
      '/scripts/stage-a-gate.mjs',
      '/scripts/stage-a-yaml-entry.mjs',
      '/scripts/STAGE-A-YAML-NOTICE.md',
      '/vendor/stage-a-yaml-parser.mjs',
      '/scripts/write-stage-a-artifact.mjs',
      '/scripts/verify-stage-a-artifact.mjs',
      '/scripts/verify-workflows.mjs',
      '/scripts/verify-node.mjs'
    ]) {
      expect(entries).toContain(`${pattern} @wbizmo`);
    }
  });

  it('rejects a floating Node version in the trusted Stage A runtime', () => {
    const workflows = Object.fromEntries(
      readdirSync('.github/workflows')
        .filter((name) => /\.ya?ml$/u.test(name))
        .map((name) => [
          name,
          readFileSync(path.join('.github/workflows', name), 'utf8')
        ])
    );
    const stageA = workflows['stage-a.yml'];
    if (!stageA) throw new Error('Stage A workflow fixture is missing');
    workflows['stage-a.yml'] = stageA.replace(
      "node-version: '24.22.1'",
      "node-version: '24'"
    );

    const result = run(workflows);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      'trusted Stage A runtime must use an exact, supported Node.js patch version'
    );
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

  it('requires the trusted Stage A gate for pull_request_target and pins actions', () => {
    const result = run({
      'ci.yml': safe('{ pull_request_target: {} }').replace(SHA, 'v4')
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      'only stage-a.yml may use pull_request_target'
    );
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
      'push',
      'schedule',
      'workflow_run'
    ]);
    expect(doc.on.workflow_run).toMatchObject({
      workflows: ['Stage A Trusted Pre-execution Gate'],
      types: ['completed'],
      branches: ['main']
    });
    expect(Object.keys(doc.jobs)).toEqual(['stage-a-result', 'analyze']);
    expect(doc.jobs.analyze.needs).toBe('stage-a-result');
    expect(doc.jobs.analyze.steps[0].with.ref).toContain(
      'needs.stage-a-result.outputs.merge_sha'
    );
    expect(
      readFileSync('.github/workflows/pr-quality.yml', 'utf8')
    ).not.toMatch(/codeql-action/);
  });
});
