import { Command } from 'commander';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerPolicyCommand } from '../../src/commands/policy.js';
import { canonicalJson } from '../../src/core/canonical-json.js';

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
        decisionSha256: string;
        policy: { sourceSha256: string };
      };
      expect(result.decision).toBe('incomplete');
      expect(result.decisionSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(result.policy.sourceSha256).toHaveLength(64);
      expect(process.exitCode).toBe(3);
      const sarif = JSON.parse(await readFile(sarifPath, 'utf8')) as {
        runs: Array<{
          invocations: Array<{
            executionSuccessful: boolean;
            properties: Record<string, unknown>;
          }>;
        }>;
      };
      expect(sarif.runs[0]?.invocations[0]?.executionSuccessful).toBe(false);
      expect(sarif.runs[0]?.invocations[0]?.properties).toMatchObject({
        policyDecision: 'incomplete',
        policySha256: result.decisionSha256
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

  it('rejects a repository-owned organization policy even with explicit trust', async () => {
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
      await program.parseAsync(
        [
          'policy',
          'check',
          '--path',
          root,
          '--organization-policy',
          path.join(root, '.toolip', 'policy.yaml'),
          '--organization-policy-public-key',
          path.join(root, 'trusted.pub'),
          '--organization-policy-key-id',
          'org-key-v1',
          '--organization-policy-issuer',
          'security.example/toolip',
          '--offline'
        ],
        { from: 'user' }
      );
      const result = JSON.parse(output.join('')) as {
        decision: string;
        reasons: string[];
      };
      expect(result).toMatchObject({
        decision: 'misconfigured',
        reasons: [
          'organization policy must resolve outside the scanned project root'
        ]
      });
      expect(process.exitCode).toBe(1);
    } finally {
      process.exitCode = previous;
      write.mockRestore();
    }
  });

  it('rejects a repository-owned organization trust key', async () => {
    const root = await fixture('version: 1\nminimumSeverity: high\n');
    const trustRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-org-policy-')
    );
    roots.push(trustRoot);
    const policyPath = path.join(trustRoot, 'organization-policy.json');
    await writeFile(policyPath, '{}');
    const publicKeyPath = path.join(root, 'repository-trust.pub');
    await writeFile(publicKeyPath, 'untrusted key data');
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
        [
          'policy',
          'check',
          '--path',
          root,
          '--offline',
          '--organization-policy',
          policyPath,
          '--organization-policy-public-key',
          publicKeyPath,
          '--organization-policy-key-id',
          'org-policy-v3',
          '--organization-policy-issuer',
          'security.example/toolip'
        ],
        { from: 'user' }
      );
      expect(JSON.parse(output.join(''))).toMatchObject({
        decision: 'misconfigured',
        reasons: [
          'organization policy trust key must resolve outside the scanned project root'
        ]
      });
    } finally {
      process.exitCode = previous;
      write.mockRestore();
    }
  });

  it('fails as misconfigured when a required organization profile is omitted', async () => {
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
      await program.parseAsync(
        [
          'policy',
          'check',
          '--path',
          root,
          '--offline',
          '--require-organization-policy'
        ],
        { from: 'user' }
      );
      expect(JSON.parse(output.join(''))).toMatchObject({
        decision: 'misconfigured',
        reasons: [
          '--require-organization-policy requires --organization-policy'
        ]
      });
      expect(process.exitCode).toBe(1);
    } finally {
      process.exitCode = previous;
      write.mockRestore();
    }
  });

  it('runs the same policy command with a signed out-of-project organization profile', async () => {
    const root = await fixture('version: 1\nminimumSeverity: low\n');
    const trustRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-org-trust-')
    );
    roots.push(trustRoot);
    const policyPath = path.join(trustRoot, 'organization-policy.json');
    const publicKeyPath = path.join(trustRoot, 'organization-policy.pub');
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    await writeFile(
      publicKeyPath,
      publicKey.export({ type: 'spki', format: 'pem' })
    );
    const issuedAt = new Date(Date.now() - 60_000).toISOString();
    const expiresAt = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000
    ).toISOString();
    const payload = {
      schema: 'toolip.dev/organization-policy/v1',
      issuer: 'security.example/toolip',
      keyId: 'org-policy-v3',
      issuedAt,
      expiresAt,
      policy: {
        version: 1,
        minimumSeverity: 'high',
        rules: {},
        suppressions: []
      }
    };
    const envelope = {
      ...payload,
      signature: {
        algorithm: 'Ed25519',
        value: cryptoSign(
          null,
          Buffer.from(canonicalJson(payload)),
          privateKey
        ).toString('base64')
      }
    };
    await writeFile(policyPath, JSON.stringify(envelope));

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
        [
          'policy',
          'check',
          '--path',
          root,
          '--offline',
          '--organization-policy',
          policyPath,
          '--organization-policy-public-key',
          publicKeyPath,
          '--organization-policy-key-id',
          'org-policy-v3',
          '--organization-policy-issuer',
          'security.example/toolip'
        ],
        { from: 'user' }
      );
      const result = JSON.parse(output.join('')) as {
        decision: string;
        decisionSha256: string;
        policy: { organizationTrusted: boolean; organizationIdentity: string };
      };
      expect(result.policy.organizationTrusted).toBe(true);
      expect(result.policy.organizationIdentity).toContain(
        'security.example/toolip:org-policy-v3:'
      );
      expect(result.decisionSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(['incomplete', 'pass', 'fail']).toContain(result.decision);
    } finally {
      process.exitCode = previous;
      write.mockRestore();
    }
  }, 30_000);
});
