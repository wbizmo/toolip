import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  evaluatePolicyAsCode,
  loadTrustedOrganizationPolicy,
  loadPolicyAsCode,
  mergePolicyLayers,
  parsePolicyAsCode,
  type PolicyAsCode,
  type PolicyLayer
} from '../../src/core/policy-as-code.js';
import { canonicalJson } from '../../src/core/canonical-json.js';

const temporaryRoots: string[] = [];
async function policyFile(contents: string): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-policy-'));
  temporaryRoots.push(root);
  const file = path.join(root, 'toolip-policy.yaml');
  await writeFile(file, contents);
  return file;
}

afterEach(async () => {
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => rm(root, { recursive: true, force: true }))
  );
});

const finding = {
  id: 'f-1',
  ruleId: 'R1',
  title: 'test',
  category: 'test',
  severity: 'high' as const,
  confidence: 'high' as const,
  message: 'bad',
  source: 'unit',
  location: { file: 'src/a.ts' }
};
const policy: PolicyAsCode = {
  version: 1,
  rules: { R1: { severity: 'info' } },
  suppressions: [
    {
      id: 'accepted',
      ruleId: 'R1',
      expiresAt: '2030-01-01T00:00:00.000Z',
      reason: 'reviewed'
    }
  ]
};

describe('versioned policy-as-code evaluation', () => {
  it('parses strict versioned YAML and fingerprints source bytes', async () => {
    const result = await loadPolicyAsCode(
      await policyFile('version: 1\nrules:\n  R1:\n    severity: high\n')
    );
    expect(result.policy.version).toBe(1);
    expect(result.sha256).toHaveLength(64);
  });

  it('hashes policy meaning canonically regardless of object insertion order', () => {
    const first: PolicyAsCode = {
      version: 1,
      minimumSeverity: 'high',
      rules: { R1: { severity: 'critical' }, R2: { enabled: true } },
      suppressions: []
    };
    const second = {
      suppressions: [],
      rules: { R2: { enabled: true }, R1: { severity: 'critical' } },
      minimumSeverity: 'high',
      version: 1
    } satisfies PolicyAsCode;
    const evaluate = (value: PolicyAsCode) =>
      evaluatePolicyAsCode({
        policy: value,
        trust: { trusted: false, source: 'repository' },
        findings: [],
        analysisState: 'complete'
      });

    expect(evaluate(first).policySha256).toBe(evaluate(second).policySha256);
  });

  it('rejects duplicate keys, unknown fields, and unsupported versions', async () => {
    await expect(
      loadPolicyAsCode(await policyFile('version: 1\nversion: 1\n'))
    ).rejects.toThrow('malformed or contains duplicate');
    await expect(
      loadPolicyAsCode(await policyFile('version: 1\nunknown: true\n'))
    ).rejects.toThrow('supported versioned schema');
    await expect(
      loadPolicyAsCode(await policyFile('version: 2\n'))
    ).rejects.toThrow('supported versioned schema');
  });

  it('bounds suppression work and rejects unsafe suppression paths', () => {
    const suppression = {
      id: 'bounded',
      ruleId: 'R1',
      path: 'src/**',
      expiresAt: '2030-01-01T00:00:00.000Z',
      reason: 'reviewed'
    };
    expect(() =>
      parsePolicyAsCode(
        JSON.stringify({
          version: 1,
          suppressions: Array.from({ length: 1_001 }, (_, index) => ({
            ...suppression,
            id: `bounded-${index}`
          }))
        })
      )
    ).toThrow('supported versioned schema');
    expect(() =>
      parsePolicyAsCode(
        JSON.stringify({
          version: 1,
          suppressions: [{ ...suppression, path: '../outside/**' }]
        })
      )
    ).toThrow('supported versioned schema');
  });

  it('does not honor privileged suppressions or disables from untrusted policy', () => {
    const result = evaluatePolicyAsCode({
      policy,
      trust: { trusted: false, source: 'repository' },
      findings: [finding],
      analysisState: 'complete',
      now: new Date('2029-01-01T00:00:00Z')
    });
    expect(result.decision).toBe('fail');
    expect(result.findings[0]?.severity).toBe('high');
    expect(result.suppressed).toEqual([]);
  });

  it('honors an unexpired suppression only with trusted provenance', () => {
    const result = evaluatePolicyAsCode({
      policy,
      trust: { trusted: true, source: 'signed' },
      findings: [finding],
      analysisState: 'complete',
      now: new Date('2029-01-01T00:00:00Z')
    });
    expect(result.decision).toBe('pass');
    expect(result.suppressed).toEqual(['accepted']);
  });

  it('never calls an incomplete scan a pass, even with no findings', () => {
    const result = evaluatePolicyAsCode({
      policy: { version: 1, rules: {}, suppressions: [] },
      trust: { trusted: false, source: 'repository' },
      findings: [],
      analysisState: 'partial'
    });
    expect(result.decision).toBe('incomplete');
  });

  it('blocks CISA KEV findings independently of severity when requested', () => {
    const kevFinding = {
      ...finding,
      category: 'vulnerability',
      severity: 'low' as const,
      metadata: { exploitIntel: { knownExploited: true } }
    };
    const result = evaluatePolicyAsCode({
      policy: {
        version: 1,
        blockKnownExploited: true,
        minimumSeverity: 'critical',
        rules: {},
        suppressions: []
      },
      trust: { trusted: true, source: 'signed' },
      findings: [kevFinding],
      analysisState: 'complete'
    });

    expect(result.decision).toBe('fail');
    expect(result.findings).toContainEqual(kevFinding);
    expect(result.reasons).toContainEqual(
      expect.stringContaining('listed in CISA KEV')
    );
  });

  it('does not let a local fail-on override weaken signed organization severity', () => {
    const result = evaluatePolicyAsCode({
      policy: {
        version: 1,
        minimumSeverity: 'high',
        rules: {},
        suppressions: []
      },
      trust: {
        trusted: true,
        source: 'signed',
        identity: 'security.example/toolip:org-key-v1:policy-digest'
      },
      findings: [finding],
      analysisState: 'complete',
      minimumSeverity: 'critical'
    });

    expect(result.decision).toBe('fail');
    expect(result.findings).toContainEqual(finding);
  });

  it('fails closed below minimum coverage and gates only selected rule sets', () => {
    const belowCoverage = evaluatePolicyAsCode({
      policy: { version: 1, minimumCoverage: 0.9, rules: {}, suppressions: [] },
      trust: { trusted: false, source: 'repository' },
      findings: [],
      analysisState: 'complete',
      coverage: { eligible: 10, scanned: 8 }
    });
    expect(belowCoverage.decision).toBe('incomplete');
    expect(belowCoverage.reasons[0]).toContain('below policy minimum');

    const scoped = evaluatePolicyAsCode({
      policy: {
        version: 1,
        ruleSets: ['secrets'],
        rules: {},
        suppressions: []
      },
      trust: { trusted: false, source: 'repository' },
      findings: [
        { ...finding, category: 'infrastructure' },
        { ...finding, id: 'f-secret', category: 'secrets' }
      ],
      analysisState: 'complete'
    });
    expect(scoped.decision).toBe('fail');
    expect(scoped.findings.map(({ id }) => id)).toEqual(['f-secret']);
  });

  it('keeps untrusted organization overlays strict and grants suppressions only when approved', () => {
    const repository: PolicyAsCode = {
      version: 1,
      minimumSeverity: 'high',
      minimumCoverage: 0.8,
      rules: { R1: { enabled: false } },
      suppressions: [
        {
          id: 'repo-suppression',
          ruleId: 'R1',
          expiresAt: '2035-01-01T00:00:00.000Z',
          reason: 'repository cannot silence'
        }
      ]
    };
    const organization: PolicyLayer = {
      policy: {
        version: 1,
        minimumSeverity: 'low',
        minimumCoverage: 0.5,
        rules: { R1: {} },
        suppressions: [
          {
            id: 'org-suppression',
            ruleId: 'R1',
            expiresAt: '2035-01-01T00:00:00.000Z',
            reason: 'approved exception'
          }
        ]
      },
      trust: { trusted: false, source: 'user-config' }
    };
    const untrusted = mergePolicyLayers(repository, organization);
    expect(untrusted.policy.minimumSeverity).toBe('high');
    expect(untrusted.policy.minimumCoverage).toBe(0.8);
    expect(untrusted.policy.suppressions).toEqual([]);

    const selfAsserted = mergePolicyLayers(repository, {
      ...organization,
      trust: { trusted: true, source: 'user-config' }
    });
    expect(selfAsserted.policy.suppressions).toEqual([]);
    expect(selfAsserted.trust.trusted).toBe(false);

    const approved = mergePolicyLayers(repository, {
      ...organization,
      trust: {
        trusted: true,
        source: 'signed',
        identity: 'example-issuer:test-key:verified-envelope'
      }
    });
    const result = evaluatePolicyAsCode({
      policy: approved.policy,
      trust: approved.trust,
      findings: [finding],
      analysisState: 'complete',
      coverage: { eligible: 1, scanned: 1 },
      now: new Date('2030-01-01T00:00:00.000Z')
    });
    expect(result.decision).toBe('pass');
    expect(result.suppressed).toEqual(['org-suppression']);
  });

  it('requires a valid unexpired Ed25519 organization envelope and trusted issuer', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-org-policy-'));
    temporaryRoots.push(root);
    const filePath = path.join(root, 'organization-policy.json');
    const publicKeyPath = path.join(root, 'organization-policy.pub');
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    await writeFile(
      publicKeyPath,
      publicKey.export({ type: 'spki', format: 'pem' })
    );
    const payload = {
      schema: 'toolip.dev/organization-policy/v1',
      issuer: 'security.example/toolip',
      keyId: 'org-policy-v3',
      issuedAt: '2030-01-01T00:00:00.000Z',
      expiresAt: '2030-02-01T00:00:00.000Z',
      policy: {
        version: 1,
        minimumSeverity: 'high',
        rules: {},
        suppressions: []
      }
    };
    const makeEnvelope = (value = payload) => ({
      ...value,
      signature: {
        algorithm: 'Ed25519',
        value: cryptoSign(
          null,
          Buffer.from(canonicalJson(value)),
          privateKey
        ).toString('base64')
      }
    });
    await writeFile(filePath, JSON.stringify(makeEnvelope()));
    const verified = await loadTrustedOrganizationPolicy({
      filePath,
      publicKeyPath,
      trustedKeyId: 'org-policy-v3',
      trustedIssuer: 'security.example/toolip',
      now: Date.parse('2030-01-15T00:00:00.000Z')
    });
    expect(verified.policy.minimumSeverity).toBe('high');
    expect(verified.identity).toContain(
      'security.example/toolip:org-policy-v3:'
    );
    await expect(
      loadTrustedOrganizationPolicy({
        filePath,
        publicKeyPath,
        trustedKeyId: 'attacker-key',
        trustedIssuer: 'security.example/toolip',
        now: Date.parse('2030-01-15T00:00:00.000Z')
      })
    ).rejects.toThrow('signer or issuer is not trusted');
    await expect(
      loadTrustedOrganizationPolicy({
        filePath,
        publicKeyPath,
        trustedKeyId: 'org-policy-v3',
        trustedIssuer: 'security.example/toolip',
        now: Date.parse('2030-03-01T00:00:00.000Z')
      })
    ).rejects.toThrow('expired or has invalid validity dates');
    const changed = {
      ...payload,
      policy: { ...payload.policy, minimumSeverity: 'info' }
    };
    await writeFile(filePath, JSON.stringify(makeEnvelope(changed)));
    const { privateKey: otherPrivateKey } = generateKeyPairSync('ed25519');
    const forged = {
      ...payload,
      signature: {
        algorithm: 'Ed25519',
        value: cryptoSign(
          null,
          Buffer.from(canonicalJson(payload)),
          otherPrivateKey
        ).toString('base64')
      }
    };
    await writeFile(filePath, JSON.stringify(forged));
    await expect(
      loadTrustedOrganizationPolicy({
        filePath,
        publicKeyPath,
        trustedKeyId: 'org-policy-v3',
        trustedIssuer: 'security.example/toolip',
        now: Date.parse('2030-01-15T00:00:00.000Z')
      })
    ).rejects.toThrow('signature verification failed');
  });

  it('does not honor expired or path-mismatched suppressions', () => {
    const noMatch: PolicyAsCode = {
      ...policy,
      suppressions: [
        {
          id: 'expired',
          ruleId: 'R1',
          path: 'tests/**',
          expiresAt: '2020-01-01T00:00:00.000Z',
          reason: 'old'
        }
      ]
    };
    const result = evaluatePolicyAsCode({
      policy: noMatch,
      trust: { trusted: true, source: 'signed' },
      findings: [finding],
      analysisState: 'complete',
      minimumSeverity: 'info',
      now: new Date('2029-01-01T00:00:00Z')
    });
    expect(result.decision).toBe('misconfigured');
    expect(result.findings[0]?.severity).toBe('info');
    expect(result.suppressed).toEqual([]);
    expect(result.reasons[0]).toContain('expired suppression');
  });

  it('rejects expired policy suppressions even when no finding matches them', () => {
    const result = evaluatePolicyAsCode({
      policy: {
        version: 1,
        rules: {},
        suppressions: [
          {
            id: 'expired-unused',
            ruleId: 'R2',
            expiresAt: '2020-01-01T00:00:00.000Z',
            reason: 'old exception'
          }
        ]
      },
      trust: { trusted: false, source: 'repository' },
      findings: [],
      analysisState: 'complete',
      now: new Date('2029-01-01T00:00:00Z')
    });

    expect(result.decision).toBe('misconfigured');
    expect(result.reasons[0]).toContain('expired-unused');
  });
});
