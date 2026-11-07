import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createReport } from '../../src/core/report.js';
import {
  canonicalEvidenceJson,
  scannerArtifactDigest,
  signReportEvidence,
  verifyReportEvidence
} from '../../src/core/report-signature.js';
import type { Finding } from '../../src/contracts/finding.js';
import { fileURLToPath } from 'node:url';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateKeyPem = privateKey
  .export({ type: 'pkcs8', format: 'pem' })
  .toString();
const publicKeyPem = publicKey
  .export({ type: 'spki', format: 'pem' })
  .toString();

function report() {
  const finding = {
    id: 'finding-1',
    ruleId: 'TLP-TEST-001',
    title: 'Test finding',
    severity: 'high',
    category: 'test',
    message: 'A deterministic test finding.',
    confidence: 'high',
    location: { file: 'src/a.ts', line: 4 },
    remediation: { summary: 'Fix the test fixture.' }
  } satisfies Finding;
  return createReport({
    version: '3.2.1-rc',
    command: 'scan',
    root: '/workspace/project',
    findings: [finding],
    analysis: {
      state: 'partial',
      reasons: ['one provider is unavailable'],
      coverage: {
        state: 'partial',
        eligible: 4,
        scanned: 3,
        skipped: 1,
        failed: 0,
        excluded: 0
      }
    }
  });
}

const signer = (scanReport = report()) =>
  signReportEvidence(scanReport, {
    privateKeyPem,
    keyId: 'test-key-1',
    projectId: 'org/repository',
    scannerArtifactSha256: 'd'.repeat(64),
    issuedAt: '2026-01-01T00:00:00.000Z',
    subject: {
      gitRevision: 'a'.repeat(40),
      lockGraphDigest: 'b'.repeat(64),
      configDigest: 'c'.repeat(64)
    }
  });

function verify(scanReport: ReturnType<typeof signer>, overrides = {}) {
  return verifyReportEvidence(scanReport, {
    publicKeyPem,
    trustedKeyId: 'test-key-1',
    expectedProjectId: 'org/repository',
    now: Date.parse('2026-01-02T00:00:00.000Z'),
    ...overrides
  });
}

describe('signed report evidence', () => {
  it('computes a stable digest for the complete runtime module tree', async () => {
    const entry = fileURLToPath(new URL('../../src/index.ts', import.meta.url));
    const first = await scannerArtifactDigest(entry);
    const second = await scannerArtifactDigest(entry);
    expect(first).toMatch(/^[a-f0-9]{64}$/u);
    expect(second).toBe(first);
  });

  it('canonicalizes object key order and omits nondeterministic report fields', () => {
    expect(canonicalEvidenceJson({ z: 1, a: { y: 2, b: 3 } })).toBe(
      '{"a":{"b":3,"y":2},"z":1}'
    );
    const first = signer();
    const second = signer({
      ...report(),
      generatedAt: '2030-04-05T06:07:08.000Z',
      root: 'C:\\project'
    });
    expect(first.evidenceSignature?.payloadSha256).toBe(
      second.evidenceSignature?.payloadSha256
    );
    expect(first.evidenceSignature?.signature).toBe(
      second.evidenceSignature?.signature
    );
  });

  it('preserves __proto__ evidence keys and rejects cyclic canonical data', () => {
    const evidence = JSON.parse(
      '{"value":1,"__proto__":{"polluted":true}}'
    ) as Record<string, unknown>;
    expect(Object.hasOwn(evidence, '__proto__')).toBe(true);
    expect(canonicalEvidenceJson(evidence)).toBe(
      '{"__proto__":{"polluted":true},"value":1}'
    );
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalEvidenceJson(cyclic)).toThrow(/cyclic/u);

    const source = report();
    const originalFinding = source.findings[0];
    if (!originalFinding) throw new Error('fixture report needs a finding');
    const signed = signer({
      ...source,
      findings: [
        {
          ...originalFinding,
          metadata: evidence as Finding['metadata']
        }
      ]
    });
    expect(verify(signed).status).toBe('verified');
    const alteredEvidence = JSON.parse(
      '{"value":1,"__proto__":{"polluted":false}}'
    ) as Record<string, unknown>;
    const alteredReport = {
      ...signed,
      findings: signed.findings.map((finding) => ({
        ...finding,
        metadata: alteredEvidence as Finding['metadata']
      }))
    };
    expect(verify(alteredReport)).toEqual({
      status: 'invalid',
      reason: 'payload-mismatch'
    });
  });

  it('verifies a valid signature and invalidates any finding or coverage change', () => {
    const signed = signer();
    expect(verify(signed)).toMatchObject({ status: 'verified' });

    const findingChanged = {
      ...signed,
      findings: signed.findings.map((finding) => ({
        ...finding,
        message: 'changed'
      }))
    };
    expect(verify(findingChanged)).toEqual({
      status: 'invalid',
      reason: 'payload-mismatch'
    });

    const analysis = signed.analysis;
    if (!analysis?.coverage) throw new Error('fixture report needs coverage');
    const coverageChanged = {
      ...signed,
      analysis: {
        ...analysis,
        coverage: { ...analysis.coverage, skipped: 0 }
      }
    };
    expect(verify(coverageChanged)).toEqual({
      status: 'invalid',
      reason: 'payload-mismatch'
    });
  });

  it('marks unsigned, expired, wrong-key and wrong-project evidence unverified', () => {
    expect(
      verifyReportEvidence(report(), {
        publicKeyPem,
        trustedKeyId: 'test-key-1',
        expectedProjectId: 'org/repository'
      })
    ).toEqual({ status: 'unsigned', reason: 'signature-missing' });

    const signed = signer();
    expect(
      verify(signed, { now: Date.parse('2026-06-01T00:00:00.000Z') })
    ).toEqual({
      status: 'expired',
      reason: 'signature-expired'
    });
    expect(verify(signed, { trustedKeyId: 'another-key' })).toEqual({
      status: 'untrusted',
      reason: 'key-id-mismatch'
    });
    expect(verify(signed, { expectedProjectId: 'org/other' })).toEqual({
      status: 'untrusted',
      reason: 'project-id-mismatch'
    });
    expect(
      verify(signed, { expectedScannerArtifactSha256: 'e'.repeat(64) })
    ).toEqual({ status: 'untrusted', reason: 'scanner-artifact-mismatch' });
  });

  it('binds key identity and issue time so an attacker cannot relabel or refresh a signature', () => {
    const signed = signer();
    const envelope = signed.evidenceSignature;
    if (!envelope) throw new Error('fixture report must be signed');

    const relabeled = {
      ...signed,
      evidenceSignature: { ...envelope, keyId: 'rotated-key' }
    };
    expect(verify(relabeled, { trustedKeyId: 'rotated-key' })).toEqual({
      status: 'invalid',
      reason: 'payload-mismatch'
    });

    const refreshed = {
      ...signed,
      evidenceSignature: {
        ...envelope,
        issuedAt: '2026-06-01T00:00:00.000Z'
      }
    };
    expect(
      verify(refreshed, { now: Date.parse('2026-06-01T00:00:00.000Z') })
    ).toEqual({
      status: 'invalid',
      reason: 'payload-mismatch'
    });
  });
});
