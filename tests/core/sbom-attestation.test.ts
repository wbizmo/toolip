import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalSbomJson,
  signSbomAttestation,
  verifySbomAttestation
} from '../../src/core/sbom/attestation.js';

const keys = generateKeyPairSync('ed25519');
const privateKeyPem = keys.privateKey
  .export({ type: 'pkcs8', format: 'pem' })
  .toString();
const publicKeyPem = keys.publicKey
  .export({ type: 'spki', format: 'pem' })
  .toString();
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components: [{ name: 'example', version: '1.0.0' }]
};

function signed(document = sbom) {
  return signSbomAttestation(document, {
    privateKeyPem,
    keyId: 'release-key-1',
    projectId: 'acme/payments',
    toolipVersion: '3.2.1-rc',
    scannerArtifactSha256: 'd'.repeat(64),
    issuedAt: '2026-11-07T00:00:00.000Z',
    source: { gitRevision: 'a'.repeat(40), lockGraphDigest: 'b'.repeat(64) }
  });
}

function verify(document: unknown, attestation: unknown, overrides = {}) {
  return verifySbomAttestation(document, attestation, {
    publicKeyPem,
    trustedKeyId: 'release-key-1',
    expectedProjectId: 'acme/payments',
    now: Date.parse('2026-11-08T00:00:00.000Z'),
    ...overrides
  });
}

describe('DSSE SBOM attestations', () => {
  it('canonicalizes JSON and verifies a standard DSSE signature over an in-toto subject', () => {
    expect(canonicalSbomJson({ z: 1, a: { y: 2, x: 3 } })).toBe(
      '{"a":{"x":3,"y":2},"z":1}'
    );
    const attestation = signed();
    expect(attestation.payloadType).toBe('application/vnd.in-toto+json');
    expect(verify(sbom, attestation)).toMatchObject({
      status: 'verified',
      projectId: 'acme/payments',
      keyId: 'release-key-1'
    });
  });

  it('preserves __proto__ as signed SBOM data and rejects cyclic documents', () => {
    const document = JSON.parse(
      '{"name":"fixture","__proto__":{"polluted":true}}'
    ) as Record<string, unknown>;
    expect(canonicalSbomJson(document)).toBe(
      '{"__proto__":{"polluted":true},"name":"fixture"}'
    );
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalSbomJson(cyclic)).toThrow(/cyclic/u);

    const attestedDocument = JSON.parse(
      '{"name":"fixture","__proto__":{"polluted":true}}'
    ) as Record<string, unknown>;
    const attestation = signed(attestedDocument);
    expect(verify(attestedDocument, attestation).status).toBe('verified');
    const changedDocument = JSON.parse(
      '{"name":"fixture","__proto__":{"polluted":false}}'
    ) as Record<string, unknown>;
    expect(verify(changedDocument, attestation)).toEqual({
      status: 'invalid',
      reason: 'subject'
    });
  });

  it('rejects changed SBOMs, wrong identities, stale evidence and malformed envelopes', () => {
    const attestation = signed();
    expect(verify({ ...sbom, components: [] }, attestation)).toEqual({
      status: 'invalid',
      reason: 'subject'
    });
    expect(
      verify(sbom, attestation, { expectedProjectId: 'acme/other' })
    ).toEqual({ status: 'untrusted', reason: 'project-id' });
    expect(verify(sbom, attestation, { trustedKeyId: 'another-key' })).toEqual({
      status: 'untrusted',
      reason: 'key-id'
    });
    expect(
      verify(sbom, attestation, { now: Date.parse('2027-02-10T00:00:00.000Z') })
    ).toEqual({ status: 'invalid', reason: 'expired' });
    expect(
      verify(sbom, { payloadType: 'invalid', payload: '', signatures: [] })
    ).toEqual({
      status: 'invalid',
      reason: 'malformed'
    });
  });

  it('rejects modified signed payloads and future-issued statements', () => {
    const attestation = signed();
    expect(
      verify(sbom, {
        ...attestation,
        signatures: [
          { keyid: 'release-key-1', sig: Buffer.alloc(64).toString('base64') }
        ]
      })
    ).toEqual({ status: 'invalid', reason: 'signature' });

    const future = signSbomAttestation(sbom, {
      privateKeyPem,
      keyId: 'release-key-1',
      projectId: 'acme/payments',
      toolipVersion: '3.2.1-rc',
      scannerArtifactSha256: 'd'.repeat(64),
      issuedAt: '2027-01-01T00:00:00.000Z'
    });
    expect(verify(sbom, future)).toEqual({
      status: 'invalid',
      reason: 'issued-in-future'
    });
  });

  it('can require an independently reviewed scanner artifact digest', () => {
    const attestation = signed();
    expect(
      verify(sbom, attestation, {
        expectedScannerArtifactSha256: 'e'.repeat(64)
      })
    ).toEqual({ status: 'untrusted', reason: 'scanner-artifact' });
    expect(
      verify(sbom, attestation, {
        expectedScannerArtifactSha256: 'd'.repeat(64)
      })
    ).toMatchObject({
      status: 'verified',
      scannerArtifactSha256: 'd'.repeat(64)
    });
  });
});
