import {
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify
} from 'node:crypto';
import { canonicalJson } from '../canonical-json.js';

const payloadType = 'application/vnd.in-toto+json';
const statementType = 'https://in-toto.io/Statement/v1';
const predicateType = 'https://toolip.dev/attestation/sbom/v1';
const maximumPayloadBytes = 32 * 1024 * 1024;
const maximumIdentityLength = 256;
const futureClockSkewMs = 5 * 60 * 1000;

export type DsseSbomAttestation = Readonly<{
  payloadType: typeof payloadType;
  payload: string;
  signatures: readonly Readonly<{ keyid: string; sig: string }>[];
}>;

export type SbomAttestationVerification =
  | {
      status: 'verified';
      projectId: string;
      keyId: string;
      sbomSha256: string;
      scannerArtifactSha256: string;
    }
  | {
      status: 'invalid';
      reason:
        'malformed' | 'signature' | 'subject' | 'expired' | 'issued-in-future';
    }
  | {
      status: 'untrusted';
      reason: 'key-id' | 'project-id' | 'scanner-artifact';
    };

export function canonicalSbomJson(document: unknown): string {
  return canonicalJson(document);
}

function validateIdentity(projectId: string, keyId: string): void {
  if (
    !projectId ||
    projectId.trim() !== projectId ||
    projectId.length > maximumIdentityLength ||
    [...projectId].some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  )
    throw new TypeError('SBOM project ID is invalid');
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(keyId))
    throw new TypeError('SBOM signing key ID is invalid');
}

function pae(type: string, payload: Uint8Array): Buffer {
  const typeBytes = Buffer.from(type, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${typeBytes.length} `, 'utf8'),
    typeBytes,
    Buffer.from(` ${payload.length} `, 'utf8'),
    Buffer.from(payload)
  ]);
}

function decodePayload(attestation: DsseSbomAttestation): Buffer | undefined {
  if (
    !attestation ||
    attestation.payloadType !== payloadType ||
    typeof attestation.payload !== 'string' ||
    attestation.payload.length > Math.ceil((maximumPayloadBytes * 4) / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      attestation.payload
    )
  )
    return undefined;
  const payload = Buffer.from(attestation.payload, 'base64');
  if (
    payload.length > maximumPayloadBytes ||
    payload.toString('base64') !== attestation.payload
  )
    return undefined;
  return payload;
}

/** Create a DSSE envelope with an in-toto statement for the canonical SBOM. */
export function signSbomAttestation(
  document: unknown,
  input: {
    privateKeyPem: string;
    keyId: string;
    projectId: string;
    toolipVersion: string;
    scannerArtifactSha256: string;
    issuedAt?: string;
    source?: Readonly<Record<string, string>>;
  }
): DsseSbomAttestation {
  validateIdentity(input.projectId, input.keyId);
  if (!input.toolipVersion || input.toolipVersion.length > 128)
    throw new TypeError('SBOM Toolip version is invalid');
  if (!/^[a-f0-9]{64}$/u.test(input.scannerArtifactSha256))
    throw new TypeError('SBOM scanner artifact digest is invalid');
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(issuedAt)))
    throw new TypeError('SBOM issue time is invalid');
  const sbomBytes = Buffer.from(canonicalSbomJson(document), 'utf8');
  if (sbomBytes.length === 0 || sbomBytes.length > maximumPayloadBytes)
    throw new RangeError('SBOM exceeds the attestation input limit');
  const sbomSha256 = createHash('sha256').update(sbomBytes).digest('hex');
  const statement = {
    _type: statementType,
    subject: [{ name: 'toolip-sbom', digest: { sha256: sbomSha256 } }],
    predicateType,
    predicate: {
      projectId: input.projectId,
      keyId: input.keyId,
      toolipVersion: input.toolipVersion,
      scannerArtifactSha256: input.scannerArtifactSha256,
      issuedAt,
      source: input.source ?? {}
    }
  };
  const payload = Buffer.from(canonicalSbomJson(statement), 'utf8');
  if (payload.length > maximumPayloadBytes)
    throw new RangeError('SBOM attestation exceeds the payload limit');
  const signature = cryptoSign(
    null,
    pae(payloadType, payload),
    input.privateKeyPem
  ).toString('base64');
  return Object.freeze({
    payloadType,
    payload: payload.toString('base64'),
    signatures: Object.freeze([
      Object.freeze({ keyid: input.keyId, sig: signature })
    ])
  });
}

/** Verify DSSE signature, exact canonical SBOM subject, project/key trust and age. */
export function verifySbomAttestation(
  document: unknown,
  attestationValue: unknown,
  input: {
    publicKeyPem: string;
    trustedKeyId: string;
    expectedProjectId: string;
    expectedScannerArtifactSha256?: string;
    now?: number;
    maxAgeMs?: number;
  }
): SbomAttestationVerification {
  let attestation: DsseSbomAttestation;
  try {
    validateIdentity(input.expectedProjectId, input.trustedKeyId);
    if (!attestationValue || typeof attestationValue !== 'object')
      return { status: 'invalid', reason: 'malformed' };
    attestation = attestationValue as DsseSbomAttestation;
    if (
      attestation.payloadType !== payloadType ||
      !Array.isArray(attestation.signatures) ||
      attestation.signatures.length !== 1
    )
      return { status: 'invalid', reason: 'malformed' };
  } catch {
    return { status: 'untrusted', reason: 'project-id' };
  }
  const signatureRecord = attestation.signatures[0];
  if (!signatureRecord || typeof signatureRecord.keyid !== 'string')
    return { status: 'invalid', reason: 'malformed' };
  if (signatureRecord.keyid !== input.trustedKeyId)
    return { status: 'untrusted', reason: 'key-id' };
  if (!/^[A-Za-z0-9+/]{86}==$/u.test(signatureRecord.sig ?? ''))
    return { status: 'invalid', reason: 'malformed' };
  const payload = decodePayload(attestation);
  if (!payload) return { status: 'invalid', reason: 'malformed' };
  let statement: Record<string, unknown>;
  try {
    statement = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(payload)
    );
  } catch {
    return { status: 'invalid', reason: 'malformed' };
  }
  const predicate = statement.predicate as Record<string, unknown> | undefined;
  if (predicate?.projectId !== input.expectedProjectId)
    return { status: 'untrusted', reason: 'project-id' };
  if (predicate?.keyId !== input.trustedKeyId)
    return { status: 'untrusted', reason: 'key-id' };
  const scannerArtifactSha256 = predicate?.scannerArtifactSha256;
  if (
    typeof scannerArtifactSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/u.test(scannerArtifactSha256)
  )
    return { status: 'invalid', reason: 'malformed' };
  if (
    input.expectedScannerArtifactSha256 !== undefined &&
    (!/^[a-f0-9]{64}$/u.test(input.expectedScannerArtifactSha256) ||
      scannerArtifactSha256 !== input.expectedScannerArtifactSha256)
  )
    return { status: 'untrusted', reason: 'scanner-artifact' };
  const issuedAt = predicate?.issuedAt;
  if (typeof issuedAt !== 'string' || !Number.isFinite(Date.parse(issuedAt)))
    return { status: 'invalid', reason: 'malformed' };
  const now = input.now ?? Date.now();
  const issuedTime = Date.parse(issuedAt);
  if (issuedTime - now > futureClockSkewMs)
    return { status: 'invalid', reason: 'issued-in-future' };
  const maxAgeMs = input.maxAgeMs ?? 90 * 24 * 60 * 60 * 1000;
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0)
    return { status: 'invalid', reason: 'malformed' };
  if (now - issuedTime > maxAgeMs)
    return { status: 'invalid', reason: 'expired' };
  let sbomBytes: Buffer;
  try {
    if (!document || typeof document !== 'object' || Array.isArray(document))
      return { status: 'invalid', reason: 'malformed' };
    sbomBytes = Buffer.from(canonicalSbomJson(document), 'utf8');
  } catch {
    return { status: 'invalid', reason: 'malformed' };
  }
  if (sbomBytes.length > maximumPayloadBytes)
    return { status: 'invalid', reason: 'malformed' };
  const sbomSha256 = createHash('sha256').update(sbomBytes).digest('hex');
  const subject = statement.subject;
  if (
    statement._type !== statementType ||
    statement.predicateType !== predicateType ||
    !Array.isArray(subject) ||
    subject.length !== 1 ||
    subject[0]?.name !== 'toolip-sbom' ||
    subject[0]?.digest?.sha256 !== sbomSha256
  )
    return { status: 'invalid', reason: 'subject' };
  let valid = false;
  try {
    valid = cryptoVerify(
      null,
      pae(payloadType, payload),
      input.publicKeyPem,
      Buffer.from(signatureRecord.sig, 'base64')
    );
  } catch {
    return { status: 'invalid', reason: 'malformed' };
  }
  if (!valid) return { status: 'invalid', reason: 'signature' };
  return {
    status: 'verified',
    projectId: input.expectedProjectId,
    keyId: input.trustedKeyId,
    sbomSha256,
    scannerArtifactSha256
  };
}
