import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { Parser } from 'tar';
import { PackageURL } from 'packageurl-js';
import { parseDocument } from 'yaml';
import { canonicalJson } from './canonical-json.js';
import {
  verifySigstoreBundleWithIdentity,
  type SigstoreIdentityPolicy
} from '../providers/npm/provenance.js';
import type { Bundle, SignOptions } from 'sigstore';

const payloadType = 'application/vnd.in-toto+json';
const statementType = 'https://in-toto.io/Statement/v1';
const predicateType = 'https://toolip.dev/attestation/npm-package/v1';
const maximumTarballBytes = 32 * 1024 * 1024;
const maximumUnpackedBytes = 128 * 1024 * 1024;
const maximumTarEntries = 100_000;
const maximumManifestBytes = 1024 * 1024;
const maximumStatementBytes = 1024 * 1024;
const futureClockSkewMs = 5 * 60 * 1000;

export type NpmTarballAttestation = Bundle;

export type NpmTarballAttestationVerification = Readonly<{
  status: 'verified' | 'invalid' | 'untrusted';
  reason:
    | 'verified'
    | 'malformed'
    | 'subject_mismatch'
    | 'source_repository_mismatch'
    | 'source_commit_mismatch'
    | 'scanner_artifact_mismatch'
    | 'issued_in_future'
    | 'signature';
  packageName?: string;
  packageVersion?: string;
  tarballSha512?: string;
  sourceRepository?: string;
  sourceCommit?: string;
  scannerArtifactSha256?: string;
}>;

type NpmPackageIdentity = Readonly<{ name: string; version: string }>;
type PackageStatement = Readonly<{
  _type: typeof statementType;
  subject: readonly Readonly<{
    name: string;
    digest: Readonly<{ sha512: string }>;
  }>[];
  predicateType: typeof predicateType;
  predicate: Readonly<{
    sourceRepository: string;
    sourceCommit: string;
    toolipVersion: string;
    scannerArtifactSha256: string;
    issuedAt: string;
  }>;
}>;

type Attest = (
  payload: Buffer,
  payloadType: string,
  options: SignOptions
) => Promise<Bundle>;
type VerifyBundle = (
  bundle: Record<string, unknown>,
  trust: SigstoreIdentityPolicy,
  signal?: AbortSignal
) => Promise<boolean>;

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    return undefined;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) return undefined;
  }
  return value as Record<string, unknown>;
}

function normalizeGitHubRepository(value: string): string {
  if (value.length > 2048 || /\p{Cc}/u.test(value))
    throw new TypeError('npm attestation source repository is invalid.');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('npm attestation source repository is invalid.');
  }
  const segments = url.pathname.split('/').filter(Boolean);
  if (
    url.protocol !== 'https:' ||
    url.hostname.toLowerCase() !== 'github.com' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    segments.length !== 2 ||
    segments.some((segment) => segment === '.' || segment === '..')
  )
    throw new TypeError(
      'npm attestation source repository must be a GitHub repository URL.'
    );
  const owner = segments[0];
  const name = segments[1]?.replace(/\.git$/iu, '');
  if (
    !owner ||
    !name ||
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})$/u.test(owner) ||
    !/^[A-Za-z0-9_.-]{1,100}$/u.test(name)
  )
    throw new TypeError('npm attestation source repository is invalid.');
  return `https://github.com/${owner}/${name}`.toLowerCase();
}

function packagePurl(name: string, version: string): string {
  const scoped = name.startsWith('@');
  const parts = scoped ? name.slice(1).split('/') : [name];
  if (
    (scoped && parts.length !== 2) ||
    parts.some((part) => !part || /[\\\s]/u.test(part)) ||
    !version ||
    /\s/u.test(version)
  )
    throw new TypeError('npm package identity is invalid.');
  return new PackageURL(
    'npm',
    scoped ? `@${parts[0]}` : undefined,
    parts.at(-1) ?? '',
    version
  ).toString();
}

function tarballSha512(tarball: Buffer): string {
  if (
    !Buffer.isBuffer(tarball) ||
    tarball.length === 0 ||
    tarball.length > maximumTarballBytes
  )
    throw new RangeError('npm package tarball is empty or exceeds 32 MiB.');
  return createHash('sha512').update(tarball).digest('hex');
}

function isCanonicalUtcTimestamp(value: string): boolean {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

/** Parse the exact package manifest from an in-memory npm tgz without extracting files. */
export async function readNpmTarballIdentity(
  tarball: Buffer
): Promise<NpmPackageIdentity> {
  tarballSha512(tarball);
  const archive = gunzipSync(tarball, {
    maxOutputLength: maximumUnpackedBytes
  });
  const parser = new Parser({
    strict: true,
    gzip: false,
    maxMetaEntrySize: maximumManifestBytes
  });
  let totalBytes = 0;
  let entryCount = 0;
  let manifestBytes: Buffer | undefined;
  let manifestChunks: Buffer[] = [];
  let manifestSize = 0;
  let manifestReadBytes = 0;
  let manifestSeen = false;
  let failed: Error | undefined;

  parser.on('entry', (entry) => {
    entryCount += 1;
    const entryPath = entry.path;
    const validEntrySize = Number.isSafeInteger(entry.size) && entry.size >= 0;
    if (validEntrySize) totalBytes += entry.size;
    if (
      entryCount > maximumTarEntries ||
      !validEntrySize ||
      totalBytes > maximumUnpackedBytes ||
      entryPath.startsWith('/') ||
      entryPath.includes('\\') ||
      entryPath.split('/').some((part: string) => part === '.' || part === '..')
    ) {
      failed = new Error('npm package tarball exceeds structural limits.');
      parser.abort(failed);
      return;
    }
    if (entryPath !== 'package/package.json') {
      // The tar parser pauses while an entry is unread. Drain every member
      // we do not inspect so an attacker cannot stall verification with an
      // arbitrary file before or after package.json.
      entry.resume();
      return;
    }
    if (
      manifestSeen ||
      entry.type !== 'File' ||
      entry.size > maximumManifestBytes
    ) {
      failed = new Error(
        'npm package tarball has an invalid package manifest.'
      );
      parser.abort(failed);
      return;
    }
    manifestSeen = true;
    manifestSize = entry.size;
    entry.on('data', (chunk: Buffer) => {
      manifestReadBytes += chunk.length;
      manifestChunks.push(Buffer.from(chunk));
    });
    entry.once('end', () => {
      manifestBytes = Buffer.concat(manifestChunks, manifestSize);
      manifestChunks = [];
      if (manifestReadBytes !== manifestSize) {
        failed = new Error('npm package manifest content is truncated.');
        parser.abort(failed);
      }
    });
  });

  try {
    await new Promise<void>((resolve, reject) => {
      parser.once('end', resolve);
      parser.once('error', reject);
      parser.end(archive);
    });
  } catch (error) {
    throw failed ?? error;
  }
  if (failed) throw failed;
  if (!manifestBytes || manifestBytes.length !== manifestSize)
    throw new Error(
      'npm package tarball does not contain package/package.json.'
    );
  const source = new TextDecoder('utf-8', { fatal: true }).decode(
    manifestBytes
  );
  const document = parseDocument(source, {
    uniqueKeys: true,
    prettyErrors: false
  });
  if (document.errors.length)
    throw new Error('npm package manifest is malformed or has duplicate keys.');
  const manifest = asRecord(JSON.parse(source) as unknown);
  if (
    !manifest ||
    typeof manifest.name !== 'string' ||
    typeof manifest.version !== 'string'
  )
    throw new Error('npm package manifest identity is missing.');
  packagePurl(manifest.name, manifest.version);
  return Object.freeze({ name: manifest.name, version: manifest.version });
}

function buildStatement(
  identity: NpmPackageIdentity,
  sha512: string,
  input: {
    sourceRepository: string;
    sourceCommit: string;
    toolipVersion: string;
    scannerArtifactSha256: string;
    issuedAt: string;
  }
): PackageStatement {
  const sourceRepository = normalizeGitHubRepository(input.sourceRepository);
  if (!/^[a-f0-9]{40}$/iu.test(input.sourceCommit))
    throw new TypeError(
      'npm attestation source commit must be a full Git SHA.'
    );
  if (!input.toolipVersion || input.toolipVersion.length > 128)
    throw new TypeError('npm attestation Toolip version is invalid.');
  if (!/^[a-f0-9]{64}$/u.test(input.scannerArtifactSha256))
    throw new TypeError('npm attestation scanner digest is invalid.');
  if (!isCanonicalUtcTimestamp(input.issuedAt))
    throw new TypeError('npm attestation issue time is invalid.');
  return {
    _type: statementType,
    subject: [
      {
        name: packagePurl(identity.name, identity.version),
        digest: { sha512 }
      }
    ],
    predicateType,
    predicate: {
      sourceRepository,
      sourceCommit: input.sourceCommit.toLowerCase(),
      toolipVersion: input.toolipVersion,
      scannerArtifactSha256: input.scannerArtifactSha256,
      issuedAt: input.issuedAt
    }
  };
}

/** Sign the exact packed npm tarball bytes as an in-toto DSSE statement using the runner's OIDC identity. */
export async function createNpmTarballAttestation(
  tarball: Buffer,
  input: {
    sourceRepository: string;
    sourceCommit: string;
    toolipVersion: string;
    scannerArtifactSha256: string;
    issuedAt?: string;
    attest?: Attest;
  }
): Promise<{
  bundle: NpmTarballAttestation;
  sha512: string;
  identity: NpmPackageIdentity;
}> {
  const identity = await readNpmTarballIdentity(tarball);
  if (identity.name !== 'toolip' || identity.version !== input.toolipVersion)
    throw new Error(
      'npm tarball identity must match the current Toolip package version.'
    );
  const sha512 = tarballSha512(tarball);
  const statement = buildStatement(identity, sha512, {
    sourceRepository: input.sourceRepository,
    sourceCommit: input.sourceCommit,
    toolipVersion: input.toolipVersion,
    scannerArtifactSha256: input.scannerArtifactSha256,
    issuedAt: input.issuedAt ?? new Date().toISOString()
  });
  const payload = Buffer.from(canonicalJson(statement), 'utf8');
  if (payload.length > maximumStatementBytes)
    throw new RangeError('npm package attestation statement is too large.');
  const attest =
    input.attest ??
    (async (data, type, options) => {
      const sigstore = await import('sigstore');
      return sigstore.attest(data, type, options);
    });
  const bundle = await attest(payload, payloadType, {
    timeout: 5000,
    retry: { retries: 0 }
  });
  return { bundle, sha512, identity };
}

function statementFromBundle(value: unknown):
  | {
      bundle: Record<string, unknown>;
      statement: Record<string, unknown>;
    }
  | undefined {
  const bundle = asRecord(value);
  const envelope = asRecord(bundle?.dsseEnvelope);
  if (
    !bundle ||
    !envelope ||
    envelope.payloadType !== payloadType ||
    !Array.isArray(envelope.signatures) ||
    envelope.signatures.length !== 1 ||
    typeof envelope.payload !== 'string' ||
    envelope.payload.length > Math.ceil((maximumStatementBytes * 4) / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      envelope.payload
    )
  )
    return undefined;
  const payload = Buffer.from(envelope.payload, 'base64');
  if (
    payload.length === 0 ||
    payload.length > maximumStatementBytes ||
    payload.toString('base64') !== envelope.payload
  )
    return undefined;
  try {
    const source = new TextDecoder('utf-8', { fatal: true }).decode(payload);
    const document = parseDocument(source, {
      uniqueKeys: true,
      prettyErrors: false
    });
    if (document.errors.length) return undefined;
    const statement = asRecord(JSON.parse(source) as unknown);
    return statement ? { bundle, statement } : undefined;
  } catch {
    return undefined;
  }
}

function verificationResult(
  status: NpmTarballAttestationVerification['status'],
  reason: NpmTarballAttestationVerification['reason'],
  identity?: NpmPackageIdentity,
  sha512?: string,
  predicate?: Record<string, unknown>
): NpmTarballAttestationVerification {
  return Object.freeze({
    status,
    reason,
    ...(identity
      ? { packageName: identity.name, packageVersion: identity.version }
      : {}),
    ...(sha512 ? { tarballSha512: sha512 } : {}),
    ...(typeof predicate?.sourceRepository === 'string'
      ? { sourceRepository: predicate.sourceRepository }
      : {}),
    ...(typeof predicate?.sourceCommit === 'string'
      ? { sourceCommit: predicate.sourceCommit }
      : {}),
    ...(typeof predicate?.scannerArtifactSha256 === 'string'
      ? { scannerArtifactSha256: predicate.scannerArtifactSha256 }
      : {})
  });
}

/** Verify the exact tarball bytes, package/version subject, source and Sigstore OIDC identity. */
export async function verifyNpmTarballAttestation(
  tarball: Buffer,
  bundleValue: unknown,
  input: {
    certificateIssuer: string;
    certificateIdentity: string;
    expectedSourceRepository: string;
    expectedSourceCommit: string;
    expectedScannerArtifactSha256: string;
    now?: number;
    signal?: AbortSignal;
    verifyBundle?: VerifyBundle;
  }
): Promise<NpmTarballAttestationVerification> {
  let identity: NpmPackageIdentity;
  let sha512: string;
  try {
    identity = await readNpmTarballIdentity(tarball);
    sha512 = tarballSha512(tarball);
  } catch {
    return verificationResult('invalid', 'malformed');
  }
  const parsed = statementFromBundle(bundleValue);
  if (!parsed)
    return verificationResult('invalid', 'malformed', identity, sha512);
  const { bundle, statement } = parsed;
  const predicate = asRecord(statement.predicate);
  const subject = statement.subject;
  const subjectRecord =
    Array.isArray(subject) && subject.length === 1
      ? asRecord(subject[0])
      : undefined;
  const subjectDigest = asRecord(subjectRecord?.digest);
  let expectedRepository: string;
  try {
    expectedRepository = normalizeGitHubRepository(
      input.expectedSourceRepository
    );
  } catch {
    return verificationResult(
      'untrusted',
      'source_repository_mismatch',
      identity,
      sha512
    );
  }
  const issuedAt = predicate?.issuedAt;
  if (
    statement._type !== statementType ||
    statement.predicateType !== predicateType ||
    subjectRecord?.name !== packagePurl(identity.name, identity.version) ||
    subjectDigest?.sha512 !== sha512 ||
    typeof predicate?.sourceCommit !== 'string' ||
    !/^[a-f0-9]{40}$/iu.test(predicate.sourceCommit) ||
    typeof predicate.toolipVersion !== 'string' ||
    predicate.toolipVersion.length === 0 ||
    predicate.toolipVersion.length > 128 ||
    predicate.toolipVersion !== identity.version ||
    typeof predicate.scannerArtifactSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/u.test(predicate.scannerArtifactSha256) ||
    typeof issuedAt !== 'string' ||
    !isCanonicalUtcTimestamp(issuedAt)
  )
    return verificationResult(
      'untrusted',
      'subject_mismatch',
      identity,
      sha512,
      predicate
    );
  if (predicate.sourceRepository !== expectedRepository)
    return verificationResult(
      'untrusted',
      'source_repository_mismatch',
      identity,
      sha512,
      predicate
    );
  if (
    !/^[a-f0-9]{40}$/iu.test(input.expectedSourceCommit) ||
    predicate.sourceCommit !== input.expectedSourceCommit.toLowerCase()
  )
    return verificationResult(
      'untrusted',
      'source_commit_mismatch',
      identity,
      sha512,
      predicate
    );
  if (
    !/^[a-f0-9]{64}$/u.test(input.expectedScannerArtifactSha256) ||
    predicate.scannerArtifactSha256 !== input.expectedScannerArtifactSha256
  )
    return verificationResult(
      'untrusted',
      'scanner_artifact_mismatch',
      identity,
      sha512,
      predicate
    );
  const issuedTime = Date.parse(issuedAt);
  if (issuedTime - (input.now ?? Date.now()) > futureClockSkewMs)
    return verificationResult(
      'invalid',
      'issued_in_future',
      identity,
      sha512,
      predicate
    );
  const verifier = input.verifyBundle ?? verifySigstoreBundleWithIdentity;
  try {
    const valid = await verifier(
      bundle,
      {
        certificateIssuer: input.certificateIssuer,
        certificateIdentity: input.certificateIdentity
      },
      input.signal
    );
    return valid
      ? verificationResult('verified', 'verified', identity, sha512, predicate)
      : verificationResult('invalid', 'signature', identity, sha512, predicate);
  } catch {
    return verificationResult(
      'invalid',
      'signature',
      identity,
      sha512,
      predicate
    );
  }
}
