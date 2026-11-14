import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runSecurityDoctor } from '../../src/core/security-doctor.js';

let root: string | undefined;
afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
  root = undefined;
});

describe('SecurityDoctor malicious-content integration', () => {
  it('returns canonical chain findings and a separate coverage record', async () => {
    root = await mkdtemp(path.join(os.tmpdir(), 'toolip-malicious-content-'));
    await mkdir(path.join(root, '.vscode'));
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'fixture', scripts: { prepare: 'node init' } })
    );
    await writeFile(path.join(root, 'init'), 'eval(atob(encoded));');
    const result = await runSecurityDoctor(root);
    const finding = result.findings.find(
      (item) => item.ruleId === 'TLP-MAL-001'
    );
    expect(finding?.location?.file).toBe('package.json');
    expect(result.summary.maliciousContent).toBe(1);
    expect(result.maliciousContent.coverage.state).toBe('complete');
    expect(result.maliciousContent.filesScanned).toBeGreaterThanOrEqual(2);
  });

  it('scans index-tracked execution targets even when local ignore rules match', async () => {
    root = await mkdtemp(path.join(os.tmpdir(), 'toolip-malicious-ignored-'));
    await writeFile(path.join(root, '.toolipignore'), 'payload.orc\n');
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ scripts: { prepare: 'node payload.orc' } })
    );
    await writeFile(path.join(root, 'payload.orc'), 'eval(atob(encoded));');
    const git = (args: string[]) =>
      execFileSync('git', ['-C', root as string, ...args], { stdio: 'ignore' });
    git(['init', '-q']);
    git(['config', 'user.name', 'Toolip Test']);
    git(['config', 'user.email', 'toolip-test@example.invalid']);
    git(['add', '.toolipignore', 'package.json']);
    git(['add', '-f', 'payload.orc']);
    git(['commit', '-qm', 'fixture']);

    const result = await runSecurityDoctor(root);
    expect(
      result.findings.some((finding) => {
        const trace = finding.metadata?.trace;
        return (
          finding.ruleId === 'TLP-MAL-001' &&
          Array.isArray(trace) &&
          trace.includes('payload.orc')
        );
      })
    ).toBe(true);
    expect(result.maliciousContent.coverage.state).toBe('complete');
  });

  it('reports an unrecognized binary payload as incomplete rather than a clean scan', async () => {
    root = await mkdtemp(path.join(os.tmpdir(), 'toolip-malicious-binary-'));
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'fixture' })
    );
    await writeFile(
      path.join(root, 'opaque.payload'),
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01])
    );

    const result = await runSecurityDoctor(root);
    expect(result.maliciousContent.coverage.state).toBe('partial');
    expect(result.maliciousContent.coverage.eligible).toBeGreaterThan(0);
    expect(result.maliciousContent.coverage.skipped).toBeGreaterThan(0);
  });

  it('integrates IaC findings and scan coverage into the Security Doctor result', async () => {
    root = await mkdtemp(path.join(os.tmpdir(), 'toolip-security-doctor-iac-'));
    await mkdir(path.join(root, '.github/workflows'), { recursive: true });
    await writeFile(
      path.join(root, '.github/workflows/ci.yml'),
      ['name: CI', 'permissions:', '  contents: write'].join('\n')
    );
    const result = await runSecurityDoctor(root);
    expect(
      result.findings.some((item) => item.ruleId === 'TLP-IAC-GHA-001')
    ).toBe(true);
    expect(result.infrastructure).toMatchObject({
      coverage: { state: 'complete', eligible: 1, scanned: 1 },
      findings: 1
    });
  });
});
