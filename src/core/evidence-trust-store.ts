import { createPublicKey } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { parseDocument } from 'yaml';

const maximumTrustStoreBytes = 1024 * 1024;
const maximumKeyEntries = 100;
const maximumProjectIdLength = 256;
const maximumPemBytes = 16 * 1024;

export type EvidenceTrustKey = Readonly<{
  publicKeyPem: string;
  status: 'active' | 'revoked';
  validFrom?: string;
  expiresAt?: string;
  revokedAt?: string;
}>;

export type EvidenceTrustStore = Readonly<{
  version: 1;
  projectId: string;
  maxAgeDays: number;
  keys: Readonly<Record<string, EvidenceTrustKey>>;
}>;

export type ResolvedEvidenceTrust = Readonly<{
  publicKeyPem: string;
  trustedKeyId: string;
  expectedProjectId: string;
  maxAgeMs: number;
}>;

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

function onlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[]
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value
  );
}

function validateEd25519PublicKey(value: unknown, keyId: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > maximumPemBytes ||
    !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(
      value
    )
  )
    throw new TypeError(
      `Evidence trust key ${keyId} must be a bounded public-key PEM.`
    );
  try {
    const key = createPublicKey(value);
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519')
      throw new Error('Unsupported key type.');
  } catch {
    throw new TypeError(
      `Evidence trust key ${keyId} is not a valid Ed25519 public key.`
    );
  }
  return value;
}

/** Parse a strict external trust store with unique key IDs and explicit revocation state. */
export function parseEvidenceTrustStore(value: unknown): EvidenceTrustStore {
  const input = record(value);
  if (
    !input ||
    !onlyKeys(input, ['version', 'projectId', 'maxAgeDays', 'keys']) ||
    input.version !== 1 ||
    typeof input.projectId !== 'string' ||
    input.projectId.trim() !== input.projectId ||
    input.projectId.length === 0 ||
    input.projectId.length > maximumProjectIdLength ||
    [...input.projectId].some((character) => character.charCodeAt(0) < 0x20) ||
    !Number.isInteger(input.maxAgeDays) ||
    (input.maxAgeDays as number) < 0 ||
    (input.maxAgeDays as number) > 365
  )
    throw new TypeError('Evidence trust store identity or version is invalid.');
  const rawKeys = record(input.keys);
  if (
    !rawKeys ||
    Object.keys(rawKeys).length === 0 ||
    Object.keys(rawKeys).length > maximumKeyEntries
  )
    throw new TypeError('Evidence trust store keys are invalid.');

  const keys: Record<string, EvidenceTrustKey> = Object.create(null);
  for (const [keyId, rawKey] of Object.entries(rawKeys)) {
    const key = record(rawKey);
    if (
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(keyId) ||
      !key ||
      !onlyKeys(key, [
        'publicKeyPem',
        'status',
        'validFrom',
        'expiresAt',
        'revokedAt'
      ]) ||
      (key.status !== 'active' && key.status !== 'revoked') ||
      (key.validFrom !== undefined && !canonicalTimestamp(key.validFrom)) ||
      (key.expiresAt !== undefined && !canonicalTimestamp(key.expiresAt)) ||
      (key.revokedAt !== undefined && !canonicalTimestamp(key.revokedAt)) ||
      (key.status === 'active' && key.revokedAt !== undefined) ||
      (key.status === 'revoked' && key.revokedAt === undefined)
    )
      throw new TypeError(`Evidence trust key ${keyId} is invalid.`);
    if (
      typeof key.validFrom === 'string' &&
      typeof key.expiresAt === 'string' &&
      Date.parse(key.validFrom) >= Date.parse(key.expiresAt)
    )
      throw new TypeError(
        `Evidence trust key ${keyId} has an invalid validity interval.`
      );
    keys[keyId] = Object.freeze({
      publicKeyPem: validateEd25519PublicKey(key.publicKeyPem, keyId),
      status: key.status,
      ...(typeof key.validFrom === 'string'
        ? { validFrom: key.validFrom }
        : {}),
      ...(typeof key.expiresAt === 'string'
        ? { expiresAt: key.expiresAt }
        : {}),
      ...(typeof key.revokedAt === 'string' ? { revokedAt: key.revokedAt } : {})
    });
  }
  return Object.freeze({
    version: 1,
    projectId: input.projectId,
    maxAgeDays: input.maxAgeDays as number,
    keys: Object.freeze(keys)
  });
}

/** Resolve one active, currently valid key. Revoked keys fail closed immediately. */
export function resolveEvidenceTrust(
  store: EvidenceTrustStore,
  keyId: string,
  now = Date.now()
): ResolvedEvidenceTrust {
  if (!Number.isFinite(now))
    throw new TypeError('Evidence trust resolution clock is invalid.');
  const key = store.keys[keyId];
  if (!key) throw new Error(`Evidence key ${keyId} is not trusted.`);
  if (key.status === 'revoked')
    throw new Error(
      `Evidence key ${keyId} was revoked at ${key.revokedAt}; its signatures are not accepted.`
    );
  if (key.validFrom && now < Date.parse(key.validFrom))
    throw new Error(`Evidence key ${keyId} is not active yet.`);
  if (key.expiresAt && now >= Date.parse(key.expiresAt))
    throw new Error(`Evidence key ${keyId} has expired.`);
  return Object.freeze({
    publicKeyPem: key.publicKeyPem,
    trustedKeyId: keyId,
    expectedProjectId: store.projectId,
    maxAgeMs: store.maxAgeDays * 24 * 60 * 60 * 1000
  });
}

/** Read a bounded external trust store without following links or accepting duplicate JSON keys. */
export async function readEvidenceTrustStore(
  filePath: string,
  projectRoot: string
): Promise<EvidenceTrustStore> {
  const absolute = path.resolve(filePath);
  const named = await lstat(absolute, { bigint: true });
  if (
    named.isSymbolicLink() ||
    !named.isFile() ||
    named.size === 0n ||
    named.size > BigInt(maximumTrustStoreBytes)
  )
    throw new Error(
      'Evidence trust store must be a bounded regular non-symlink file.'
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
      'Evidence trust store must be stored outside the verified project.'
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
    const after = await lstat(absolute, { bigint: true });
    if (
      !opened.isFile() ||
      after.isSymbolicLink() ||
      opened.dev !== named.dev ||
      opened.ino !== named.ino ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size !== named.size ||
      opened.mtimeNs !== named.mtimeNs ||
      opened.ctimeNs !== named.ctimeNs ||
      opened.size > BigInt(maximumTrustStoreBytes)
    )
      throw new Error(
        'Evidence trust store changed while it was being opened.'
      );
    const buffer = Buffer.alloc(maximumTrustStoreBytes + 1);
    let size = 0;
    while (size <= maximumTrustStoreBytes) {
      const result = await handle.read(
        buffer,
        size,
        maximumTrustStoreBytes + 1 - size,
        size
      );
      if (result.bytesRead === 0) break;
      size += result.bytesRead;
    }
    const finished = await handle.stat({ bigint: true });
    if (
      size === 0 ||
      size > maximumTrustStoreBytes ||
      BigInt(size) !== opened.size ||
      finished.dev !== opened.dev ||
      finished.ino !== opened.ino ||
      finished.size !== opened.size ||
      finished.mtimeNs !== opened.mtimeNs ||
      finished.ctimeNs !== opened.ctimeNs
    )
      throw new Error('Evidence trust store changed while it was being read.');
    const source = new TextDecoder('utf-8', { fatal: true }).decode(
      buffer.subarray(0, size)
    );
    const document = parseDocument(source, {
      uniqueKeys: true,
      prettyErrors: false
    });
    if (document.errors.length)
      throw new Error(
        'Evidence trust store is malformed or has duplicate keys.'
      );
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
        'Evidence trust store path changed while it was being read.'
      );
    return parseEvidenceTrustStore(JSON.parse(source) as unknown);
  } finally {
    await handle.close();
  }
}
