import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AnalysisResultCache } from '../../src/application/task-scheduler.js';
import { canonicalEvidenceJson } from '../../src/core/report-signature.js';
import { loadRulePackFile } from '../../src/core/rule-packs.js';
import { runSecurityDoctor } from '../../src/core/security-doctor.js';

const roots: string[] = [];

afterEach(async () =>
  Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  )
);

async function temporaryDirectory(prefix: string): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  roots.push(root);
  return root;
}

function rulePackPayload() {
  return {
    schema: 'toolip.dev/rule-pack/v1',
    id: 'example',
    apiVersion: 1,
    issuedAt: '2026-11-01T00:00:00.000Z',
    expiresAt: '2026-12-01T00:00:00.000Z',
    rules: [
      {
        id: 'TLP-EXAMPLE-001',
        title: 'Example sensitive marker',
        severity: 'high',
        confidence: 'medium',
        literal: 'MATCH_SECRET_MARKER',
        fileExtensions: ['.ts'],
        remediation: 'Remove the marker and rotate any exposed credential.'
      }
    ]
  };
}

async function writePack(root: string, text: string): Promise<string> {
  const packPath = path.join(root, 'pack.json');
  await writeFile(packPath, text);
  return packPath;
}

describe('signed declarative rule packs', () => {
  it('requires an Ed25519 signature unless the local override is explicit', async () => {
    const root = await temporaryDirectory('toolip-rule-pack-');
    const unsignedPath = await writePack(
      root,
      JSON.stringify(rulePackPayload())
    );

    await expect(loadRulePackFile(unsignedPath)).rejects.toThrow(
      'Unsigned rule packs are denied by default'
    );
    await expect(
      loadRulePackFile(unsignedPath, { allowUnsignedLocalOverride: true })
    ).resolves.toMatchObject({
      id: 'example',
      trust: 'unsigned-local-override',
      rules: [{ id: 'TLP-EXAMPLE-001' }]
    });
  });

  it('verifies the trusted publisher key and rejects payload tampering', async () => {
    const root = await temporaryDirectory('toolip-rule-pack-');
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const payload = rulePackPayload();
    const signature = sign(
      null,
      Buffer.from(canonicalEvidenceJson(payload)),
      privateKey
    ).toString('base64');
    const envelope = {
      ...payload,
      signature: {
        algorithm: 'Ed25519',
        keyId: 'example-key-v1',
        value: signature
      }
    };
    const signedPath = await writePack(root, JSON.stringify(envelope));
    const publicKeyPem = publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();

    await expect(
      loadRulePackFile(signedPath, {
        publicKeyPem,
        trustedKeyId: 'example-key-v1',
        now: Date.parse('2026-11-07T00:00:00.000Z')
      })
    ).resolves.toMatchObject({ trust: 'signature', keyId: 'example-key-v1' });
    await expect(
      loadRulePackFile(signedPath, {
        publicKeyPem,
        trustedKeyId: 'another-key',
        now: Date.parse('2026-11-07T00:00:00.000Z')
      })
    ).rejects.toThrow('Rule pack signature key is not trusted');

    const tamperedPath = await writePack(
      root,
      JSON.stringify({
        ...envelope,
        rules: [{ ...payload.rules[0], literal: 'CHANGED_LITERAL' }]
      })
    );
    await expect(
      loadRulePackFile(tamperedPath, {
        publicKeyPem,
        trustedKeyId: 'example-key-v1',
        now: Date.parse('2026-11-07T00:00:00.000Z')
      })
    ).rejects.toThrow('Rule pack signature verification failed');
  });

  it('runs signed literals through the shared doctor and redacts match text', async () => {
    const root = await temporaryDirectory('toolip-rule-pack-project-');
    const packRoot = await temporaryDirectory('toolip-rule-pack-');
    const sourceRoot = path.join(root, 'src');
    await mkdir(sourceRoot);
    await writeFile(
      path.join(sourceRoot, 'sample.ts'),
      'const marker = "MATCH_SECRET_MARKER";\n'
    );
    const packPath = await writePack(
      packRoot,
      JSON.stringify(rulePackPayload())
    );
    const pack = await loadRulePackFile(packPath, {
      allowUnsignedLocalOverride: true,
      now: Date.parse('2026-11-07T00:00:00.000Z')
    });
    const cache = new AnalysisResultCache();
    const first = await runSecurityDoctor(root, {
      rulePacks: [pack],
      analysisCache: cache
    });
    const second = await runSecurityDoctor(root, {
      rulePacks: [pack],
      analysisCache: cache
    });
    const finding = first.findings.find(
      (item) => item.ruleId === 'TLP-EXAMPLE-001'
    );

    expect(finding).toMatchObject({
      severity: 'high',
      category: 'custom-rule-pack',
      location: { file: 'src/sample.ts', line: 1, column: 17 },
      metadata: { trust: 'unsigned-local-override' }
    });
    expect(JSON.stringify(finding)).not.toContain('MATCH_SECRET_MARKER');
    expect(second.findings).toEqual(first.findings);
    expect(second.cacheMetrics.hits).toBeGreaterThan(0);

    const changedPackPath = await writePack(
      packRoot,
      JSON.stringify({
        ...rulePackPayload(),
        rules: [
          {
            ...rulePackPayload().rules[0],
            literal: 'different marker'
          }
        ]
      })
    );
    const changedPack = await loadRulePackFile(changedPackPath, {
      allowUnsignedLocalOverride: true,
      now: Date.parse('2026-11-07T00:00:00.000Z')
    });
    const third = await runSecurityDoctor(root, {
      rulePacks: [changedPack],
      analysisCache: cache
    });
    expect(
      third.findings.some((item) => item.ruleId === 'TLP-EXAMPLE-001')
    ).toBe(false);
  }, 15_000);

  it('applies a trusted signed rule pack to Terraform and YAML inputs', async () => {
    const root = await temporaryDirectory('toolip-iac-rule-pack-project-');
    const packRoot = await temporaryDirectory('toolip-iac-rule-pack-');
    await mkdir(path.join(root, 'manifests'));
    await writeFile(
      path.join(root, 'main.tf'),
      'resource "aws_s3_bucket" "example" {\n  marker = "SIGNED_IAC_POLICY_MARKER"\n}\n'
    );
    await writeFile(
      path.join(root, 'manifests', 'deployment.yaml'),
      'apiVersion: apps/v1\nmetadata:\n  annotations:\n    note: SIGNED_IAC_POLICY_MARKER\n'
    );

    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const payload = {
      ...rulePackPayload(),
      rules: [
        {
          ...rulePackPayload().rules[0],
          id: 'TLP-EXAMPLE-002',
          literal: 'SIGNED_IAC_POLICY_MARKER',
          fileExtensions: ['.tf', '.yaml']
        }
      ]
    };
    const envelope = {
      ...payload,
      signature: {
        algorithm: 'Ed25519',
        keyId: 'iac-policy-v1',
        value: sign(
          null,
          Buffer.from(canonicalEvidenceJson(payload)),
          privateKey
        ).toString('base64')
      }
    };
    const packPath = await writePack(packRoot, JSON.stringify(envelope));
    const pack = await loadRulePackFile(packPath, {
      publicKeyPem: publicKey
        .export({ type: 'spki', format: 'pem' })
        .toString(),
      trustedKeyId: 'iac-policy-v1',
      now: Date.parse('2026-11-07T00:00:00.000Z')
    });

    const result = await runSecurityDoctor(root, { rulePacks: [pack] });
    const findings = result.findings.filter(
      (finding) => finding.ruleId === 'TLP-EXAMPLE-002'
    );

    expect(pack.trust).toBe('signature');
    expect(findings.map((finding) => finding.location?.file)).toEqual([
      'main.tf',
      'manifests/deployment.yaml'
    ]);
    expect(
      findings.every((finding) => finding.source === 'signed-rule-pack:example')
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('SIGNED_IAC_POLICY_MARKER');
  }, 15_000);

  it('rejects executable-shaped rules and expired packs', async () => {
    const root = await temporaryDirectory('toolip-rule-pack-');
    const invalid = {
      ...rulePackPayload(),
      rules: [
        {
          ...rulePackPayload().rules[0],
          id: 'TLP-EXAMPLE-001',
          literal: 'x',
          javascript: 'import("./plugin.js")'
        }
      ]
    };
    const invalidPath = await writePack(root, JSON.stringify(invalid));
    await expect(
      loadRulePackFile(invalidPath, {
        allowUnsignedLocalOverride: true,
        now: Date.parse('2026-11-07T00:00:00.000Z')
      })
    ).rejects.toThrow('invalid or unsafe rule');

    const expiredPath = await writePack(
      root,
      JSON.stringify({
        ...rulePackPayload(),
        expiresAt: '2026-11-02T00:00:00.000Z'
      })
    );
    await expect(
      loadRulePackFile(expiredPath, {
        allowUnsignedLocalOverride: true,
        now: Date.parse('2026-11-07T00:00:00.000Z')
      })
    ).rejects.toThrow('expired');
  });
});
