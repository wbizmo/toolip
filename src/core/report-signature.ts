import {
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify
} from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson } from './canonical-json.js';
import type { ToolipReport } from './report.js';

export type ReportEvidenceSignature = Readonly<{
  schema: 'toolip.dev/evidence/v2';
  algorithm: 'Ed25519';
  keyId: string;
  projectId: string;
  issuedAt: string;
  scannerArtifactSha256: string;
  subject: Readonly<{
    gitRevision?: string;
    gitIndexDigest?: string;
    lockGraphDigest?: string;
    configDigest?: string;
  }>;
  payloadSha256: string;
  signature: string;
}>;

export type ReportEvidenceVerification =
  | { status: 'unsigned'; reason: 'signature-missing' }
  | {
      status: 'untrusted';
      reason:
        'key-id-mismatch' | 'project-id-mismatch' | 'scanner-artifact-mismatch';
    }
  | { status: 'expired'; reason: 'signature-expired' }
  | {
      status: 'invalid';
      reason:
        | 'malformed-signature'
        | 'payload-mismatch'
        | 'signature-invalid'
        | 'issued-in-future';
    }
  | {
      status: 'verified';
      payloadSha256: string;
      scannerArtifactSha256: string;
      keyId: string;
      projectId: string;
    };

const MAX_PROJECT_ID_LENGTH = 256;
const MAX_KEY_ID_LENGTH = 128;
const FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_ARTIFACT_FILES = 20_000;
const MAX_ARTIFACT_FILE_BYTES = 4 * 1024 * 1024;
const MAX_ARTIFACT_TOTAL_BYTES = 64 * 1024 * 1024;

/** Canonical JSON with lexicographically sorted object keys and stable arrays. */
export function canonicalEvidenceJson(value: unknown): string {
  return canonicalJson(value);
}

function validateIdentity(projectId: string, keyId: string): void {
  if (
    !projectId.trim() ||
    projectId.trim() !== projectId ||
    projectId.length > MAX_PROJECT_ID_LENGTH ||
    [...projectId].some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  )
    throw new TypeError('evidence project ID is invalid');
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(keyId) ||
    keyId.length > MAX_KEY_ID_LENGTH
  )
    throw new TypeError('evidence signing key ID is invalid');
}

function signedPayload(
  report: ToolipReport,
  projectId: string,
  subject: ReportEvidenceSignature['subject'],
  scannerArtifactSha256: string,
  keyId: string,
  issuedAt: string
): unknown {
  const {
    generatedAt: _generatedAt,
    root: _root,
    evidenceSignature: _signature,
    ...stableReport
  } = report;
  return {
    schema: 'toolip.dev/evidence/v2',
    projectId,
    keyId,
    issuedAt,
    scannerArtifactSha256,
    subject,
    report: stableReport
  };
}

/** Hashes the installed Toolip package metadata and its complete runtime module tree. */
export async function scannerArtifactDigest(
  entryFile = process.argv[1]
): Promise<string> {
  if (!entryFile) throw new Error('Toolip scanner entry point is unavailable.');
  const resolvedEntry = await realpath(path.resolve(entryFile));
  let directory = path.dirname(resolvedEntry);
  let packageRoot: string | undefined;
  for (let depth = 0; depth < 8; depth++) {
    const manifestPath = path.join(directory, 'package.json');
    try {
      const manifestBytes = await readArtifactFile(manifestPath, 256 * 1024);
      const manifest = JSON.parse(manifestBytes.toString('utf8')) as {
        name?: unknown;
      };
      if (manifest.name === 'toolip') {
        packageRoot = directory;
        break;
      }
    } catch {
      // Continue up only for a missing or non-Toolip package manifest.
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  if (!packageRoot)
    throw new Error('Toolip package root could not be identified.');

  const runtimeCandidates = ['dist/src', 'src'].map((relative) =>
    path.join(packageRoot as string, relative)
  );
  const runtimeRoot = runtimeCandidates.find((candidate) =>
    isPathWithin(candidate, resolvedEntry)
  );
  if (!runtimeRoot)
    throw new Error(
      'Toolip scanner entry is outside the package runtime tree.'
    );

  const files: Array<{ absolute: string; relative: string }> = [];
  const directories: Array<{
    absolute: string;
    dev: bigint;
    ino: bigint;
    mtimeNs: bigint;
    ctimeNs: bigint;
  }> = [];
  const pending = [runtimeRoot];
  let entriesSeen = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) continue;
    const directoryBefore = await lstat(current, { bigint: true });
    if (!directoryBefore.isDirectory() || directoryBefore.isSymbolicLink())
      throw new Error('Toolip runtime directory changed during hashing.');
    const entries = await readdir(current, { withFileTypes: true });
    const directoryAfter = await lstat(current, { bigint: true });
    if (
      !directoryAfter.isDirectory() ||
      directoryAfter.dev !== directoryBefore.dev ||
      directoryAfter.ino !== directoryBefore.ino ||
      directoryAfter.mtimeNs !== directoryBefore.mtimeNs ||
      directoryAfter.ctimeNs !== directoryBefore.ctimeNs
    )
      throw new Error('Toolip runtime directory changed during hashing.');
    directories.push({
      absolute: current,
      dev: directoryAfter.dev,
      ino: directoryAfter.ino,
      mtimeNs: directoryAfter.mtimeNs,
      ctimeNs: directoryAfter.ctimeNs
    });
    entries.sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      if (++entriesSeen > MAX_ARTIFACT_FILES)
        throw new Error('Toolip scanner artifact exceeds the file budget.');
      const absolute = path.join(current, entry.name);
      const metadata = await lstat(absolute, { bigint: true });
      if (metadata.isSymbolicLink())
        throw new Error('Toolip scanner artifact contains a symbolic link.');
      if (metadata.isDirectory()) {
        pending.push(absolute);
        continue;
      }
      if (!metadata.isFile())
        throw new Error('Toolip scanner artifact contains a special file.');
      files.push({
        absolute,
        relative: path.relative(packageRoot, absolute).split(path.sep).join('/')
      });
    }
  }
  files.push({
    absolute: path.join(packageRoot, 'package.json'),
    relative: 'package.json'
  });
  files.sort((left, right) => compareText(left.relative, right.relative));

  const digest = createHash('sha256').update('toolip-scanner-artifact-v2\0');
  let totalBytes = 0;
  for (const file of files) {
    const maximum =
      file.relative === 'package.json' ? 256 * 1024 : MAX_ARTIFACT_FILE_BYTES;
    const bytes = await readArtifactFile(file.absolute, maximum);
    totalBytes += bytes.length;
    if (totalBytes > MAX_ARTIFACT_TOTAL_BYTES)
      throw new Error('Toolip scanner artifact exceeds the byte budget.');
    digest
      .update(file.relative)
      .update('\0')
      .update(String(bytes.length))
      .update('\0')
      .update(bytes);
  }
  for (const directory of directories) {
    const current = await lstat(directory.absolute, { bigint: true });
    if (
      !current.isDirectory() ||
      current.isSymbolicLink() ||
      current.dev !== directory.dev ||
      current.ino !== directory.ino ||
      current.mtimeNs !== directory.mtimeNs ||
      current.ctimeNs !== directory.ctimeNs
    )
      throw new Error('Toolip runtime directory changed during hashing.');
  }
  return digest.digest('hex');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isPathWithin(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

async function readArtifactFile(
  filePath: string,
  maximumBytes: number
): Promise<Buffer> {
  const named = await lstat(filePath, { bigint: true });
  if (!named.isFile() || named.size > BigInt(maximumBytes))
    throw new Error(
      'Toolip scanner artifact file exceeds its regular-file budget.'
    );
  const noFollow =
    process.platform === 'win32' ? 0 : (constants.O_NOFOLLOW ?? 0);
  const handle = await open(filePath, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== named.dev ||
      opened.ino !== named.ino ||
      opened.size !== named.size ||
      opened.mtimeNs !== named.mtimeNs ||
      opened.ctimeNs !== named.ctimeNs
    )
      throw new Error('Toolip scanner artifact changed while opening.');
    const bytes = await handle.readFile();
    const current = await lstat(filePath, { bigint: true });
    if (
      bytes.length > maximumBytes ||
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== opened.dev ||
      current.ino !== opened.ino ||
      current.size !== opened.size ||
      current.mtimeNs !== opened.mtimeNs ||
      current.ctimeNs !== opened.ctimeNs
    )
      throw new Error('Toolip scanner artifact changed while reading.');
    return bytes;
  } finally {
    await handle.close();
  }
}

/** Creates a deterministic Ed25519 attestation over report data and its source identity. */
export function signReportEvidence(
  report: ToolipReport,
  input: {
    privateKeyPem: string;
    keyId: string;
    projectId: string;
    scannerArtifactSha256: string;
    issuedAt?: string;
    subject?: ReportEvidenceSignature['subject'];
  }
): ToolipReport {
  validateIdentity(input.projectId, input.keyId);
  if (!/^[a-f0-9]{64}$/u.test(input.scannerArtifactSha256))
    throw new TypeError('scanner artifact digest is invalid');
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(issuedAt)))
    throw new TypeError('evidence issue time is invalid');
  const subject = Object.freeze({ ...(input.subject ?? {}) });
  const payload = signedPayload(
    report,
    input.projectId,
    subject,
    input.scannerArtifactSha256,
    input.keyId,
    issuedAt
  );
  const canonical = canonicalEvidenceJson(payload);
  const payloadSha256 = createHash('sha256').update(canonical).digest('hex');
  const signature = cryptoSign(
    null,
    Buffer.from(canonical),
    input.privateKeyPem
  ).toString('base64');
  const evidenceSignature: ReportEvidenceSignature = Object.freeze({
    schema: 'toolip.dev/evidence/v2',
    algorithm: 'Ed25519',
    keyId: input.keyId,
    projectId: input.projectId,
    issuedAt,
    scannerArtifactSha256: input.scannerArtifactSha256,
    subject,
    payloadSha256,
    signature
  });
  return { ...report, evidenceSignature };
}

/** Verifies integrity, key/project trust and freshness without accepting unsigned evidence. */
export function verifyReportEvidence(
  report: ToolipReport,
  input: {
    publicKeyPem: string;
    trustedKeyId: string;
    expectedProjectId: string;
    expectedScannerArtifactSha256?: string;
    now?: number;
    maxAgeMs?: number;
  }
): ReportEvidenceVerification {
  const envelope = report.evidenceSignature;
  if (!envelope) return { status: 'unsigned', reason: 'signature-missing' };
  try {
    validateIdentity(input.expectedProjectId, input.trustedKeyId);
  } catch {
    return { status: 'untrusted', reason: 'project-id-mismatch' };
  }
  if (envelope.keyId !== input.trustedKeyId)
    return { status: 'untrusted', reason: 'key-id-mismatch' };
  if (envelope.projectId !== input.expectedProjectId)
    return { status: 'untrusted', reason: 'project-id-mismatch' };
  if (
    envelope.schema !== 'toolip.dev/evidence/v2' ||
    envelope.algorithm !== 'Ed25519' ||
    !Number.isFinite(Date.parse(envelope.issuedAt)) ||
    !/^[a-f0-9]{64}$/u.test(envelope.payloadSha256) ||
    !/^[a-f0-9]{64}$/u.test(envelope.scannerArtifactSha256) ||
    !/^[A-Za-z0-9+/]{86}==$/u.test(envelope.signature)
  )
    return { status: 'invalid', reason: 'malformed-signature' };
  if (
    input.expectedScannerArtifactSha256 !== undefined &&
    (!/^[a-f0-9]{64}$/u.test(input.expectedScannerArtifactSha256) ||
      input.expectedScannerArtifactSha256 !== envelope.scannerArtifactSha256)
  )
    return { status: 'untrusted', reason: 'scanner-artifact-mismatch' };
  const issuedAt = Date.parse(envelope.issuedAt);
  const now = input.now ?? Date.now();
  if (issuedAt - now > FUTURE_CLOCK_SKEW_MS)
    return { status: 'invalid', reason: 'issued-in-future' };
  const maxAgeMs = input.maxAgeMs ?? 90 * 24 * 60 * 60 * 1000;
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0)
    return { status: 'invalid', reason: 'malformed-signature' };
  if (now - issuedAt > maxAgeMs)
    return { status: 'expired', reason: 'signature-expired' };
  const payload = signedPayload(
    report,
    envelope.projectId,
    envelope.subject,
    envelope.scannerArtifactSha256,
    envelope.keyId,
    envelope.issuedAt
  );
  const canonical = canonicalEvidenceJson(payload);
  const payloadSha256 = createHash('sha256').update(canonical).digest('hex');
  if (payloadSha256 !== envelope.payloadSha256)
    return { status: 'invalid', reason: 'payload-mismatch' };
  let valid = false;
  try {
    valid = cryptoVerify(
      null,
      Buffer.from(canonical),
      input.publicKeyPem,
      Buffer.from(envelope.signature, 'base64')
    );
  } catch {
    return { status: 'invalid', reason: 'malformed-signature' };
  }
  return valid
    ? {
        status: 'verified',
        payloadSha256,
        scannerArtifactSha256: envelope.scannerArtifactSha256,
        keyId: envelope.keyId,
        projectId: envelope.projectId
      }
    : { status: 'invalid', reason: 'signature-invalid' };
}
