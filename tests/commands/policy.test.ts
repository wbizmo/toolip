import { Command } from 'commander';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerPolicyCommand } from '../../src/commands/policy.js';

const roots: string[] = [];
async function fixture(policy: string, payload = false): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-policy-cli-'));
  roots.push(root);
  await mkdir(path.join(root, '.toolip'), { recursive: true });
  await writeFile(path.join(root, '.toolip', 'policy.yaml'), policy);
  await writeFile(
    path.join(root, 'package.json'),
    JSON.stringify({
      scripts: payload ? { prepare: 'node init' } : { build: 'vite build' }
    })
  );
  if (payload) await writeFile(path.join(root, 'init'), 'eval(atob(encoded));');
  return root;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('policy check and explain commands', () => {
  it('returns incomplete for a fixture with unmeasured scorecard dimensions', async () => {
    const root = await fixture('version: 1\nminimumSeverity: high\n');
    const output: string[] = [];
    const write = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk) => {
        output.push(String(chunk));
        return true;
      });
    const previous = process.exitCode;
    try {
      const program = new Command();
      registerPolicyCommand(program);
      const sarifPath = path.join(root, 'policy.sarif');
      await program.parseAsync(
        ['policy', 'check', '--path', root, '--offline', '--sarif', sarifPath],
        {
          from: 'user'
        }
      );
      const result = JSON.parse(output.join('')) as {
        decision: string;
        policy: { sourceSha256: string };
      };
      expect(result.decision).toBe('incomplete');
      expect(result.policy.sourceSha256).toHaveLength(64);
      expect(process.exitCode).toBe(3);
      const sarif = JSON.parse(await readFile(sarifPath, 'utf8')) as {
        runs: Array<{
          invocations: Array<{ executionSuccessful: boolean; properties: Record<string, unknown> }>;
        }>;
      };
      expect(sarif.runs[0]?.invocations[0]?.executionSuccessful).toBe(false);
      expect(sarif.runs[0]?.invocations[0]?.properties).toMatchObject({
        policyDecision: 'incomplete'
      });
    } finally {
      process.exitCode = previous;
      write.mockRestore();
    }
  });

  it('fails on an untrusted policy suppression and reports findings in explain mode', async () => {
    const root = await fixture(
      'version: 1\nsuppressions:\n  - id: hidden\n    ruleId: TLP-MAL-001\n    expiresAt: 2035-01-01T00:00:00.000Z\n    reason: untrusted\n',
      true
    );
    const output: string[] = [];
    const write = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk) => {
        output.push(String(chunk));
        return true;
      });
    const previous = process.exitCode;
    try {
      const program = new Command();
      registerPolicyCommand(program);
      await program.parseAsync(
        ['policy', 'explain', '--path', root, '--offline'],
        { from: 'user' }
      );
      const result = JSON.parse(output.join('')) as {
        decision: string;
        findings: Array<{ ruleId: string }>;
      };
      expect(result.decision).toBe('incomplete');
      expect(
        result.findings.some((finding) => finding.ruleId === 'TLP-MAL-001')
      ).toBe(true);
      expect(process.exitCode).toBe(3);
    } finally {
      process.exitCode = previous;
      write.mockRestore();
    }
  });
});
