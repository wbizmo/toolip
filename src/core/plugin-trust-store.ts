import { createPublicKey } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { parseDocument } from 'yaml';

const maximumStoreBytes = 1024 * 1024;
const maximumKeys = 100;
const maximumPemBytes = 16 * 1024;

export type PluginTrustKey = Readonly<{
  publicKeyPem: string;
  status: 'active' | 'revoked';
  validFrom?: string;
  expiresAt?: string;
  revokedAt?: string;
}>;

export type PluginTrustStore = Readonly<{
  version: 1;
  keys: Readonly<Record<string, PluginTrustKey>>;
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

function validatePublicKey(value: unknown, keyId: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > maximumPemBytes ||
    !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(
      value
    )
  )
    throw new TypeError(
      `Plugin trust key ${keyId} must be a bounded public PEM.`
    );
  try {
    const key = createPublicKey(value);
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519')
      throw new Error('Unsupported key type.');
  } catch {
    throw new TypeError(`Plugin trust key ${keyId} is not Ed25519.`);
  }
  return value;
}

export function parsePluginTrustStore(value: unknown): PluginTrustStore {
  const input = record(value);
  if (!input || !onlyKeys(input, ['version', 'keys']) || input.version !== 1)
    throw new TypeError('Plugin trust store must be version 1.');
  const rawKeys = record(input.keys);
  if (
    !rawKeys ||
    Object.keys(rawKeys).length === 0 ||
    Object.keys(rawKeys).length > maximumKeys
  )
    throw new TypeError('Plugin trust store keys are invalid.');
  const keys: Record<string, PluginTrustKey> = Object.create(null);
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
      throw new TypeError(`Plugin trust key ${keyId} is invalid.`);
    if (
      typeof key.validFrom === 'string' &&
      typeof key.expiresAt === 'string' &&
      Date.parse(key.validFrom) >= Date.parse(key.expiresAt)
    )
      throw new TypeError(
        `Plugin trust key ${keyId} has an invalid validity interval.`
      );
    keys[keyId] = Object.freeze({
      publicKeyPem: validatePublicKey(key.publicKeyPem, keyId),
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
  return Object.freeze({ version: 1, keys: Object.freeze(keys) });
}

export function resolvePluginTrustKey(
  store: PluginTrustStore,
  keyId: string,
  now = Date.now()
): Readonly<{ publicKeyPem: string; trustedKeyId: string }> {
  if (!Number.isFinite(now))
    throw new TypeError('Plugin trust resolution clock is invalid.');
  const key = store.keys[keyId];
  if (!key) throw new Error(`Plugin signing key ${keyId} is not trusted.`);
  if (key.status === 'revoked')
    throw new Error(`Plugin signing key ${keyId} is revoked.`);
  if (key.validFrom && now < Date.parse(key.validFrom))
    throw new Error(`Plugin signing key ${keyId} is not active yet.`);
  if (key.expiresAt && now >= Date.parse(key.expiresAt))
    throw new Error(`Plugin signing key ${keyId} has expired.`);
  return Object.freeze({ publicKeyPem: key.publicKeyPem, trustedKeyId: keyId });
}

/** Load an operator-owned plugin trust store kept outside the scanned project. */
export async function readPluginTrustStore(
  filePath: string,
  projectRoot: string
): Promise<PluginTrustStore> {
  const absolute = path.resolve(filePath);
  const named = await lstat(absolute, { bigint: true });
  if (
    named.isSymbolicLink() ||
    !named.isFile() ||
    named.size === 0n ||
    named.size > BigInt(maximumStoreBytes)
  )
    throw new Error(
      'Plugin trust store must be a bounded regular non-symlink file.'
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
      'Plugin trust store must be stored outside the scanned project.'
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
      opened.size > BigInt(maximumStoreBytes)
    )
      throw new Error('Plugin trust store changed while it was being opened.');
    const buffer = Buffer.alloc(maximumStoreBytes + 1);
    let size = 0;
    while (size <= maximumStoreBytes) {
      const result = await handle.read(
        buffer,
        size,
        maximumStoreBytes + 1 - size,
        size
      );
      if (result.bytesRead === 0) break;
      size += result.bytesRead;
    }
    const finished = await handle.stat({ bigint: true });
    if (
      size === 0 ||
      size > maximumStoreBytes ||
      BigInt(size) !== opened.size ||
      finished.dev !== opened.dev ||
      finished.ino !== opened.ino ||
      finished.size !== opened.size ||
      finished.mtimeNs !== opened.mtimeNs ||
      finished.ctimeNs !== opened.ctimeNs
    )
      throw new Error('Plugin trust store changed while it was being read.');
    const source = new TextDecoder('utf-8', { fatal: true }).decode(
      buffer.subarray(0, size)
    );
    const document = parseDocument(source, {
      uniqueKeys: true,
      prettyErrors: false
    });
    if (document.errors.length)
      throw new Error('Plugin trust store is malformed or has duplicate keys.');
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
        'Plugin trust store path changed while it was being read.'
      );
    return parsePluginTrustStore(JSON.parse(source) as unknown);
  } finally {
    await handle.close();
  }
}
