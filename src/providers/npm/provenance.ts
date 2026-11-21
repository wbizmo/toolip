import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { PackageURL } from 'packageurl-js';
import { parseDocument } from 'yaml';
import type { DependencyIdentity } from '../../core/dependencies/inventory.js';

const registryOrigin = 'https://registry.npmjs.org';
const maximumPolicyBytes = 1024 * 1024;
const maximumResponseBytes = 8 * 1024 * 1024;
const maximumArtifactBytes = 32 * 1024 * 1024;
const maximumAttestations = 100;
const maximumStatementBytes = 1024 * 1024;
const sigstoreWorkerTimeoutMs = 20_000;
const provenancePredicate = 'https://slsa.dev/provenance/v1';

export type NpmProvenanceTrust = Readonly<{
  certificateIssuer: string;
  certificateIdentity: string;
  sourceRepository: string;
}>;

export type NpmProvenancePolicy = Readonly<{
  version: 1;
  packages: Readonly<Record<string, NpmProvenanceTrust>>;
}>;

export type NpmProvenanceVerification = Readonly<{
  /** Stable digest of package name, version, registry and lock integrity. */
  identityDigest: string;
  name: string;
  version: string;
  status:
    | 'verified'
    | 'not_configured'
    | 'withheld'
    | 'unavailable'
    | 'untrusted'
    | 'invalid';
  reason:
    | 'verified'
    | 'no_package_policy'
    | 'private_scope_consent_required'
    | 'registry_not_public_npm'
    | 'lock_integrity_missing'
    | 'registry_metadata_unavailable'
    | 'response_too_large'
    | 'registry_identity_mismatch'
    | 'artifact_integrity_mismatch'
    | 'artifact_fetch_unavailable'
    | 'no_attestation'
    | 'subject_mismatch'
    | 'repository_mismatch'
    | 'signature_invalid'
    | 'signature_verification_timeout'
    | 'request_timeout'
    | 'attestation_malformed'
    | 'cancelled';
  sourceRepository?: string;
  certificateIssuer?: string;
  certificateIdentity?: string;
  /** Actual archive bytes, independently of publisher identity and code safety. */
  artifactIntegrity: 'verified' | 'declared-not-verified' | 'mismatch';
}>;

type PackageRecord = Readonly<{
  name: string;
  version: string;
  id?: string;
  dist: Readonly<{
    integrity?: string;
    tarball?: string;
    attestations?: Readonly<{ url: string }>;
  }>;
}>;

type AttestationRecord = Readonly<{
  predicateType: string;
  bundle: Record<string, unknown>;
}>;

type VerifyBundle = (
  bundle: Record<string, unknown>,
  trust: NpmProvenanceTrust,
  signal?: AbortSignal
) => Promise<boolean>;

export type SigstoreIdentityPolicy = Pick<
  NpmProvenanceTrust,
  'certificateIssuer' | 'certificateIdentity'
>;

export type NpmProvenanceOptions = {
  policy?: NpmProvenancePolicy;
  allowPublicScope?: boolean;
  signal?: AbortSignal;
  requestTimeoutMs?: number;
  fetchImplementation?: typeof fetch;
  verifyBundle?: VerifyBundle;
};

function record(value: unknown): Record<string, unknown> | undefined {
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

function hasOnlyKeys(
  value: Record<string, unknown>,
  keys: readonly string[]
): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function httpsIdentity(value: unknown, field: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 2048 ||
    /\p{Cc}/u.test(value)
  )
    throw new TypeError(`npm provenance ${field} is invalid.`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`npm provenance ${field} is invalid.`);
  }
  if (url.protocol !== 'https:' || url.username || url.password)
    throw new TypeError(`npm provenance ${field} must be an HTTPS identity.`);
  return value;
}

function normalizeGitHubRepository(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 2048) return undefined;
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:' ||
      url.hostname.toLowerCase() !== 'github.com' ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      return undefined;
    const segments = url.pathname.split('/').filter(Boolean);
    if (
      segments.length !== 2 ||
      segments.some((segment) => segment === '.' || segment === '..')
    )
      return undefined;
    const owner = segments[0];
    const repository = segments[1]?.replace(/\.git$/iu, '');
    if (
      !owner ||
      !repository ||
      !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})$/u.test(owner) ||
      !/^[A-Za-z0-9_.-]{1,100}$/u.test(repository)
    )
      return undefined;
    return `https://github.com/${owner}/${repository}`.toLowerCase();
  } catch {
    return undefined;
  }
}

/** Parse a user-owned policy. Unknown fields and ambiguous identities are rejected. */
export function parseNpmProvenancePolicy(value: unknown): NpmProvenancePolicy {
  const input = record(value);
  if (
    !input ||
    !hasOnlyKeys(input, ['version', 'packages']) ||
    input.version !== 1
  )
    throw new TypeError('npm provenance policy must be version 1.');
  const packagesInput = record(input.packages);
  if (
    !packagesInput ||
    Object.keys(packagesInput).length === 0 ||
    Object.keys(packagesInput).length > 5000
  )
    throw new TypeError('npm provenance policy package rules are invalid.');
  const packages: Record<string, NpmProvenanceTrust> = Object.create(null);
  for (const [name, rawTrust] of Object.entries(packagesInput)) {
    const versionSeparator = name.lastIndexOf('@');
    const packageName =
      versionSeparator > 0 ? name.slice(0, versionSeparator) : name;
    const exactVersion =
      versionSeparator > 0 ? name.slice(versionSeparator + 1) : undefined;
    if (
      !/^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/u.test(packageName) ||
      packageName.length > 214 ||
      (exactVersion !== undefined &&
        !/^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$/u.test(exactVersion)) ||
      name.length > 350
    )
      throw new TypeError('npm provenance policy has an invalid package name.');
    const trust = record(rawTrust);
    if (
      !trust ||
      !hasOnlyKeys(trust, [
        'certificateIssuer',
        'certificateIdentity',
        'sourceRepository'
      ])
    )
      throw new TypeError(`npm provenance policy for ${name} is invalid.`);
    const certificateIssuer = httpsIdentity(trust.certificateIssuer, 'issuer');
    const certificateIdentity = httpsIdentity(
      trust.certificateIdentity,
      'certificate identity'
    );
    const sourceRepository = normalizeGitHubRepository(trust.sourceRepository);
    if (!sourceRepository || sourceRepository !== trust.sourceRepository)
      throw new TypeError(
        `npm provenance repository for ${name} must be a canonical GitHub URL.`
      );
    packages[name] = Object.freeze({
      certificateIssuer,
      certificateIdentity,
      sourceRepository
    });
  }
  return Object.freeze({ version: 1, packages: Object.freeze(packages) });
}

/** Load an operator policy from a regular file outside the scanned repository. */
export async function readNpmProvenancePolicy(
  filePath: string,
  projectRoot: string
): Promise<NpmProvenancePolicy> {
  const absolute = path.resolve(filePath);
  const named = await lstat(absolute, { bigint: true });
  if (
    named.isSymbolicLink() ||
    !named.isFile() ||
    named.size === 0n ||
    named.size > BigInt(maximumPolicyBytes)
  )
    throw new Error(
      'npm provenance policy must be a bounded regular non-symlink file.'
    );
  const [canonicalRoot, canonicalFile] = await Promise.all([
    realpath(projectRoot),
    realpath(absolute)
  ]);
  const relative = path.relative(canonicalRoot, canonicalFile);
  const outsideProject =
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative);
  if (!outsideProject)
    throw new Error(
      'npm provenance policy must be stored outside the scanned project.'
    );
  const handle = await open(
    absolute,
    constants.O_RDONLY |
      (process.platform === 'win32'
        ? 0
        : constants.O_NOFOLLOW | constants.O_NONBLOCK)
  );
  try {
    const opened = await handle.stat({ bigint: true });
    const current = await lstat(absolute, { bigint: true });
    if (
      !opened.isFile() ||
      current.isSymbolicLink() ||
      opened.dev !== named.dev ||
      opened.ino !== named.ino ||
      opened.dev !== current.dev ||
      opened.ino !== current.ino ||
      opened.size !== named.size ||
      opened.mtimeNs !== named.mtimeNs ||
      opened.ctimeNs !== named.ctimeNs ||
      opened.size > BigInt(maximumPolicyBytes)
    )
      throw new Error(
        'npm provenance policy changed while it was being opened.'
      );
    const buffer = Buffer.alloc(maximumPolicyBytes + 1);
    let size = 0;
    while (size <= maximumPolicyBytes) {
      const result = await handle.read(
        buffer,
        size,
        maximumPolicyBytes + 1 - size,
        size
      );
      if (result.bytesRead === 0) break;
      size += result.bytesRead;
    }
    const finished = await handle.stat({ bigint: true });
    if (
      size === 0 ||
      size > maximumPolicyBytes ||
      BigInt(size) !== opened.size ||
      finished.dev !== opened.dev ||
      finished.ino !== opened.ino ||
      finished.size !== opened.size ||
      finished.mtimeNs !== opened.mtimeNs ||
      finished.ctimeNs !== opened.ctimeNs
    )
      throw new Error('npm provenance policy changed while it was being read.');
    const finalPath = await lstat(absolute, { bigint: true });
    if (
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.size !== opened.size ||
      finalPath.mtimeNs !== opened.mtimeNs ||
      finalPath.ctimeNs !== opened.ctimeNs
    )
      throw new Error(
        'npm provenance policy path changed while it was being read.'
      );
    const source = new TextDecoder('utf-8', { fatal: true }).decode(
      buffer.subarray(0, size)
    );
    const document = parseDocument(source, {
      uniqueKeys: true,
      prettyErrors: false
    });
    if (document.errors.length)
      throw new Error(
        'npm provenance policy is malformed or has duplicate keys.'
      );
    const parsed: unknown = JSON.parse(source);
    return parseNpmProvenancePolicy(parsed);
  } finally {
    await handle.close();
  }
}

function result(
  identity: DependencyIdentity,
  status: NpmProvenanceVerification['status'],
  reason: NpmProvenanceVerification['reason'],
  trust?: NpmProvenanceTrust,
  artifactIntegrity: NpmProvenanceVerification['artifactIntegrity'] = 'declared-not-verified'
): NpmProvenanceVerification {
  return Object.freeze({
    identityDigest: npmProvenanceIdentityDigest(identity),
    name: identity.name,
    version: identity.version,
    status,
    reason,
    ...(status === 'verified' && trust
      ? {
          sourceRepository: trust.sourceRepository,
          certificateIssuer: trust.certificateIssuer,
          certificateIdentity: trust.certificateIdentity
        }
      : {}),
    artifactIntegrity
  });
}

export function npmProvenanceIdentityDigest(
  identity: Pick<
    DependencyIdentity,
    'name' | 'version' | 'registry' | 'integrity'
  >
): string {
  return createHash('sha256')
    .update('toolip.npm-provenance-identity/v1\0')
    .update(
      JSON.stringify([
        identity.registry ?? 'unknown',
        identity.name,
        identity.version,
        identity.integrity ?? ''
      ])
    )
    .digest('hex');
}

function digestSha512(integrity: unknown): string | undefined {
  if (typeof integrity !== 'string' || integrity.length > 1024)
    return undefined;
  const digests = new Set<string>();
  for (const token of integrity.split(/\s+/u)) {
    const match = /^sha512-([A-Za-z0-9+/]+={0,2})$/u.exec(token);
    if (!match?.[1]) continue;
    const bytes = Buffer.from(match[1], 'base64');
    if (bytes.length === 64 && bytes.toString('base64') === match[1])
      digests.add(bytes.toString('hex'));
  }
  return digests.size === 1 ? [...digests][0] : undefined;
}

async function readBoundedJson(
  response: Response,
  maximumBytes: number,
  signal: AbortSignal
): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('response-empty');
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await readChunk(reader, signal);
      if (done) break;
      if (!value) throw new Error('response-empty');
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error('response-too-large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(
      Buffer.concat(
        chunks.map((chunk) => Buffer.from(chunk)),
        total
      )
    )
  ) as unknown;
}

/** Hash exact streamed archive bytes without retaining the package tarball. */
async function readBoundedTarballSha512(
  response: Response,
  signal: AbortSignal
): Promise<string> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength && /^\d+$/u.test(declaredLength)) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length > maximumArtifactBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error('artifact-too-large');
    }
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error('artifact-empty');
  const digest = createHash('sha512');
  let total = 0;
  try {
    while (true) {
      const { done, value } = await readChunk(reader, signal);
      if (done) break;
      if (!value) throw new Error('artifact-empty');
      total += value.byteLength;
      if (total > maximumArtifactBytes) {
        await reader.cancel();
        throw new Error('artifact-too-large');
      }
      digest.update(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total === 0) throw new Error('artifact-empty');
  return digest.digest('hex');
}

function readChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal
): Promise<{ done: boolean; value?: Uint8Array }> {
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => signal.removeEventListener('abort', onAbort);
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      void reader
        .cancel()
        .catch(() => undefined)
        .finally(() => reject(abortError()));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    reader.read().then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      }
    );
  });
}

function isPublicRegistry(value: string | undefined): boolean {
  try {
    if (value === undefined) return false;
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      url.origin === registryOrigin &&
      url.pathname === '/' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash
    );
  } catch {
    return false;
  }
}

function publicTarballIdentity(value: string | undefined): string | undefined {
  if (!value || value.length > 2048) return undefined;
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:' ||
      url.origin !== registryOrigin ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      return undefined;
    return `${url.origin}${url.pathname}`;
  } catch {
    return undefined;
  }
}

function packagePurl(name: string, version: string): string {
  const scoped = name.startsWith('@');
  const parts = scoped ? name.slice(1).split('/') : [name];
  if (
    (scoped && parts.length !== 2) ||
    parts.some((part) => !part || /[\\\s]/u.test(part))
  )
    throw new Error('package-name-invalid');
  return new PackageURL(
    'npm',
    scoped ? `@${parts[0]}` : undefined,
    parts.at(-1) ?? '',
    version
  ).toString();
}

function parsePackageRecord(value: unknown): PackageRecord | undefined {
  const manifest = record(value);
  const dist = record(manifest?.dist);
  if (
    !manifest ||
    typeof manifest.name !== 'string' ||
    typeof manifest.version !== 'string' ||
    (manifest._id !== undefined && typeof manifest._id !== 'string') ||
    !dist ||
    (dist.tarball !== undefined && typeof dist.tarball !== 'string') ||
    (dist.integrity !== undefined && typeof dist.integrity !== 'string')
  )
    return undefined;
  const attestations = record(dist.attestations);
  if (attestations && typeof attestations.url !== 'string') return undefined;
  return {
    name: manifest.name,
    version: manifest.version,
    ...(typeof manifest._id === 'string' ? { id: manifest._id } : {}),
    dist: {
      ...(typeof dist.integrity === 'string'
        ? { integrity: dist.integrity }
        : {}),
      ...(typeof dist.tarball === 'string' ? { tarball: dist.tarball } : {}),
      ...(typeof attestations?.url === 'string'
        ? { attestations: { url: attestations.url } }
        : {})
    }
  };
}

function parseAttestationRecords(
  value: unknown
): AttestationRecord[] | undefined {
  const container = record(value);
  const attestations = container?.attestations;
  if (!Array.isArray(attestations) || attestations.length > maximumAttestations)
    return undefined;
  if (attestations.length === 0) return [];
  const records: AttestationRecord[] = [];
  for (const value of attestations) {
    const item = record(value);
    const bundle = record(item?.bundle);
    if (!item || typeof item.predicateType !== 'string' || !bundle)
      return undefined;
    records.push({ predicateType: item.predicateType, bundle });
  }
  return records;
}

function statementFromBundle(
  bundle: Record<string, unknown>
): Record<string, unknown> | undefined {
  const envelope = record(bundle.dsseEnvelope);
  if (
    !envelope ||
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
    return record(
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload))
    );
  } catch {
    return undefined;
  }
}

function exactSubject(
  statement: Record<string, unknown>,
  identity: DependencyIdentity,
  expectedDigest: string
): boolean {
  const subject = statement.subject;
  if (!Array.isArray(subject) || subject.length !== 1) return false;
  const packageSubject = record(subject[0]);
  const digest = record(packageSubject?.digest);
  try {
    return (
      packageSubject?.name === packagePurl(identity.name, identity.version) &&
      typeof digest?.sha512 === 'string' &&
      /^[a-f0-9]{128}$/iu.test(digest.sha512) &&
      digest.sha512.toLowerCase() === expectedDigest
    );
  } catch {
    return false;
  }
}

function sourceRepository(
  statement: Record<string, unknown>
): string | undefined {
  const predicate = record(statement.predicate);
  const buildDefinition = record(predicate?.buildDefinition);
  const externalParameters = record(buildDefinition?.externalParameters);
  const workflow = record(externalParameters?.workflow);
  return normalizeGitHubRepository(workflow?.repository);
}

function abortError(): Error {
  const error = new Error('npm provenance verification was cancelled.');
  error.name = 'AbortError';
  return error;
}

export async function verifySigstoreBundleWithIdentity(
  bundle: Record<string, unknown>,
  trust: SigstoreIdentityPolicy,
  signal?: AbortSignal
): Promise<boolean> {
  if (signal?.aborted) throw abortError();
  const workerSource = `
    const { parentPort, workerData } = require('node:worker_threads');
    const { verify } = require('sigstore');
    verify(workerData.bundle, {
      certificateIssuer: workerData.certificateIssuer,
      certificateIdentityURI: workerData.certificateIdentity,
      timeout: 5000,
      retry: { retries: 0 }
    }).then(
      () => parentPort.postMessage({ valid: true }),
      () => parentPort.postMessage({ valid: false })
    );
  `;
  const worker = new Worker(workerSource, {
    eval: true,
    workerData: {
      bundle,
      certificateIssuer: trust.certificateIssuer,
      certificateIdentity: trust.certificateIdentity
    },
    resourceLimits: { maxOldGenerationSizeMb: 64, stackSizeMb: 4 },
    env: {}
  });
  return new Promise<boolean>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(
      () => finish(undefined, new Error('sigstore verification timed out')),
      sigstoreWorkerTimeoutMs
    );
    const onAbort = (): void => finish(undefined, abortError());
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      void worker.terminate();
    };
    const finish = (valid?: boolean, error?: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve(valid === true);
    };
    worker.once('message', (message: unknown) => {
      const parsed = record(message);
      finish(parsed?.valid === true);
    });
    worker.once('error', () => finish(false));
    worker.once('exit', (code) => {
      if (code !== 0) finish(false);
    });
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Verify npm's SLSA provenance against an operator-owned exact trust rule.
 * Only the public npm registry is queried; response bytes and Sigstore worker
 * memory/time are capped. Complexity per package is O(P + T + A), where P is
 * the bounded packument, T the streamed tarball, and A the bounded attestation.
 * Peak live space is O(P + A + C), where C is the bounded streamed response
 * chunk/queue (at most the 32 MiB total tarball budget); no complete archive is
 * retained by this verifier.
 */
export async function verifyNpmProvenance(
  identity: DependencyIdentity,
  options: NpmProvenanceOptions = {}
): Promise<NpmProvenanceVerification> {
  return verifyNpmProvenanceInternal(identity, options);
}

/** Verify provenance using an archive digest established by trusted Stage A. */
export async function verifyNpmProvenanceFromVerifiedArtifactSha512(
  identity: DependencyIdentity,
  verifiedArtifactSha512: string,
  options: NpmProvenanceOptions = {}
): Promise<NpmProvenanceVerification> {
  return verifyNpmProvenanceInternal(identity, options, verifiedArtifactSha512);
}

async function verifyNpmProvenanceInternal(
  identity: DependencyIdentity,
  options: NpmProvenanceOptions = {},
  verifiedArtifactSha512?: string
): Promise<NpmProvenanceVerification> {
  let artifactIntegrity: NpmProvenanceVerification['artifactIntegrity'] =
    'declared-not-verified';
  const finish = (
    status: NpmProvenanceVerification['status'],
    reason: NpmProvenanceVerification['reason'],
    verifiedTrust?: NpmProvenanceTrust
  ): NpmProvenanceVerification =>
    result(identity, status, reason, verifiedTrust, artifactIntegrity);
  const trust =
    options.policy?.packages[`${identity.name}@${identity.version}`] ??
    options.policy?.packages[identity.name];
  if (!trust) return finish('not_configured', 'no_package_policy');
  if (identity.name.startsWith('@') && options.allowPublicScope !== true)
    return finish('withheld', 'private_scope_consent_required');
  if (!isPublicRegistry(identity.registry))
    return finish('withheld', 'registry_not_public_npm');
  const expectedDigest = digestSha512(identity.integrity);
  if (!expectedDigest) return finish('unavailable', 'lock_integrity_missing');
  const fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
  const timeoutMs = options.requestTimeoutMs ?? 5000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000)
    throw new RangeError('npm provenance request timeout is invalid.');
  const controller = new AbortController();
  let timedOut = false;
  let artifactFetchFailed = false;
  let requestTimer: ReturnType<typeof setTimeout> | undefined;
  const startRequestTimeout = (): void => {
    clearTimeout(requestTimer);
    timedOut = false;
    requestTimer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
  };
  const stopRequestTimeout = (): void => {
    clearTimeout(requestTimer);
    requestTimer = undefined;
  };
  const onAbort = (): void => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) onAbort();
  else options.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    if (controller.signal.aborted) return finish('unavailable', 'cancelled');
    const packageUrl = new URL(
      encodeURIComponent(identity.name),
      `${registryOrigin}/`
    );
    startRequestTimeout();
    let packageResponse: Response;
    let packumentValue: unknown;
    try {
      packageResponse = await fetchImplementation(packageUrl, {
        headers: {
          accept: 'application/vnd.npm.install-v1+json',
          'user-agent': 'toolip'
        },
        redirect: 'error',
        signal: controller.signal
      });
      if (
        !packageResponse.ok ||
        (packageResponse.url &&
          new URL(packageResponse.url).origin !== registryOrigin)
      ) {
        await packageResponse.body?.cancel().catch(() => undefined);
        return finish('unavailable', 'registry_metadata_unavailable');
      }
      packumentValue = await readBoundedJson(
        packageResponse,
        maximumResponseBytes,
        controller.signal
      );
    } finally {
      stopRequestTimeout();
    }
    const packument = record(packumentValue);
    const versions = record(packument?.versions);
    const manifest = parsePackageRecord(versions?.[identity.version]);
    if (
      packument?.name !== identity.name ||
      !manifest ||
      manifest.name !== identity.name ||
      manifest.version !== identity.version ||
      (manifest.id !== undefined &&
        manifest.id !== `${identity.name}@${identity.version}`) ||
      digestSha512(manifest.dist.integrity) !== expectedDigest ||
      !identity.resolved ||
      publicTarballIdentity(manifest.dist.tarball) !==
        publicTarballIdentity(identity.resolved)
    )
      return finish('untrusted', 'registry_identity_mismatch');
    const attestationUrl = manifest.dist.attestations?.url;
    let registryAttestationUrl: URL | undefined;
    let malformedAttestationUrl = false;
    if (attestationUrl) {
      try {
        const provided = new URL(attestationUrl);
        if (
          provided.protocol !== 'https:' ||
          provided.origin !== registryOrigin ||
          provided.username ||
          provided.password ||
          provided.hash ||
          !provided.pathname.startsWith('/-/npm/v1/attestations/')
        )
          malformedAttestationUrl = true;
        else
          registryAttestationUrl = new URL(
            provided.pathname,
            `${registryOrigin}/`
          );
      } catch {
        malformedAttestationUrl = true;
      }
    }

    let actualDigest: string;
    if (verifiedArtifactSha512 !== undefined) {
      if (!/^[a-f0-9]{128}$/iu.test(verifiedArtifactSha512))
        return finish('invalid', 'artifact_fetch_unavailable');
      actualDigest = verifiedArtifactSha512.toLowerCase();
    } else {
      startRequestTimeout();
      try {
        const tarballUrl = new URL(identity.resolved as string);
        const artifactResponse = await fetchImplementation(tarballUrl, {
          headers: {
            accept: 'application/octet-stream',
            'user-agent': 'toolip'
          },
          redirect: 'error',
          signal: controller.signal
        });
        if (
          !artifactResponse.ok ||
          (artifactResponse.url &&
            new URL(artifactResponse.url).origin !== registryOrigin)
        ) {
          await artifactResponse.body?.cancel().catch(() => undefined);
          throw new Error('artifact-fetch-unavailable');
        }
        actualDigest = await readBoundedTarballSha512(
          artifactResponse,
          controller.signal
        );
      } catch (error) {
        artifactFetchFailed = true;
        throw error;
      } finally {
        stopRequestTimeout();
      }
    }
    if (actualDigest !== expectedDigest) {
      artifactIntegrity = 'mismatch';
      return finish('untrusted', 'artifact_integrity_mismatch');
    }
    artifactIntegrity = 'verified';
    if (!attestationUrl) return finish('unavailable', 'no_attestation');
    if (malformedAttestationUrl || !registryAttestationUrl)
      return finish('untrusted', 'registry_identity_mismatch');

    startRequestTimeout();
    let attestationValue: unknown;
    try {
      const attestationResponse = await fetchImplementation(
        registryAttestationUrl,
        {
          headers: { accept: 'application/json', 'user-agent': 'toolip' },
          redirect: 'error',
          signal: controller.signal
        }
      );
      if (
        !attestationResponse.ok ||
        (attestationResponse.url &&
          new URL(attestationResponse.url).origin !== registryOrigin)
      ) {
        await attestationResponse.body?.cancel().catch(() => undefined);
        return finish('unavailable', 'registry_metadata_unavailable');
      }
      attestationValue = await readBoundedJson(
        attestationResponse,
        maximumResponseBytes,
        controller.signal
      );
    } finally {
      stopRequestTimeout();
    }
    const attestations = parseAttestationRecords(attestationValue);
    if (attestations?.length === 0)
      return finish('unavailable', 'no_attestation');
    if (!attestations) return finish('invalid', 'attestation_malformed');
    let subjectMatched = false;
    let repositoryMatched = false;
    for (const attestation of attestations) {
      if (attestation.predicateType !== provenancePredicate) continue;
      const statement = statementFromBundle(attestation.bundle);
      if (
        statement?._type !== 'https://in-toto.io/Statement/v1' ||
        statement?.predicateType !== provenancePredicate
      )
        continue;
      if (!exactSubject(statement, identity, expectedDigest)) continue;
      subjectMatched = true;
      if (sourceRepository(statement) !== trust.sourceRepository) continue;
      repositoryMatched = true;
      const verifyBundle =
        options.verifyBundle ?? verifySigstoreBundleWithIdentity;
      let valid: boolean;
      try {
        valid = await verifyBundle(
          attestation.bundle,
          trust,
          controller.signal
        );
      } catch {
        if (controller.signal.aborted || options.signal?.aborted)
          return result(
            identity,
            'unavailable',
            options.signal?.aborted
              ? 'cancelled'
              : timedOut
                ? 'request_timeout'
                : 'signature_verification_timeout'
          );
        valid = false;
      }
      if (valid) return finish('verified', 'verified', trust);
    }
    if (!subjectMatched) return finish('untrusted', 'subject_mismatch');
    if (!repositoryMatched) return finish('untrusted', 'repository_mismatch');
    return finish('invalid', 'signature_invalid');
  } catch (error) {
    if (options.signal?.aborted) return finish('unavailable', 'cancelled');
    if (timedOut) return finish('unavailable', 'request_timeout');
    if (
      error instanceof Error &&
      (error.message === 'response-too-large' ||
        error.message === 'artifact-too-large')
    )
      return finish('unavailable', 'response_too_large');
    if (
      artifactFetchFailed ||
      (error instanceof Error &&
        ['artifact-fetch-unavailable', 'artifact-empty'].includes(
          error.message
        ))
    )
      return finish('unavailable', 'artifact_fetch_unavailable');
    if (error instanceof SyntaxError)
      return finish('invalid', 'attestation_malformed');
    return finish('unavailable', 'registry_metadata_unavailable');
  } finally {
    stopRequestTimeout();
    options.signal?.removeEventListener('abort', onAbort);
  }
}
