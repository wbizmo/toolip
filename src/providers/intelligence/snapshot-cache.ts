import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as signBytes,
  timingSafeEqual,
  verify as verifyBytes,
  type KeyObject
} from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import type { AnalyzerCache } from '../../contracts/analyzer.js';
import {
  assertDirectoryIdentity,
  syncDirectory,
  validateRegularFileIfPresent,
  type DirectoryIdentity
} from '../../core/local-state-fs.js';
import { withLocalStateLock, type LockGuard } from '../../core/local-lock.js';

const schemaVersion = 1 as const;
const maxSnapshotBytes = 64 * 1024 * 1024;
const maxEntries = 200_000;
const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;

type StoredRecord = { storedAt: string; value: unknown };
type SnapshotPayload = {
  schemaVersion: typeof schemaVersion;
  generatedAt: string;
  records: Record<string, StoredRecord>;
};
type SnapshotSignature = {
  algorithm: 'ed25519';
  keyId: string;
  value: string;
};
type SnapshotDocument = SnapshotPayload & {
  sha256: string;
  signature?: SnapshotSignature;
};
export type AdvisorySnapshotCacheOptions = {
  now?: () => Date;
  trustedPublicKeyPem?: string;
  signingPrivateKeyPem?: string;
  signingKeyId?: string;
  requireSignature?: boolean;
};

export type SnapshotSignatureStatus = 'unsigned' | 'unverified' | 'verified';

function canonicalJson(value: unknown): string {
  if (Array.isArray(value))
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(payload: SnapshotPayload): string {
  return createHash('sha256').update(canonicalJson(payload)).digest('hex');
}

function isDate(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function signatureMessage(
  payload: SnapshotPayload,
  sha256: string,
  keyId: string
): Buffer {
  return Buffer.from(
    `toolip-advisory-snapshot-v1\0${keyId}\0${sha256}\0${canonicalJson(payload)}`,
    'utf8'
  );
}

function parseDocument(
  raw: string,
  options: Pick<
    AdvisorySnapshotCacheOptions,
    'trustedPublicKeyPem' | 'requireSignature'
  > = {}
): { document: SnapshotDocument; signatureStatus: SnapshotSignatureStatus } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error('Advisory snapshot is malformed JSON.');
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    (parsed as SnapshotDocument).schemaVersion !== schemaVersion ||
    !isDate((parsed as SnapshotDocument).generatedAt) ||
    !/^[a-f0-9]{64}$/u.test((parsed as SnapshotDocument).sha256) ||
    !parsedHasRecords(parsed)
  ) {
    throw new Error('Advisory snapshot has an unsupported or invalid schema.');
  }
  const document = parsed as SnapshotDocument;
  if (Object.keys(document.records).length > maxEntries) {
    throw new Error('Advisory snapshot exceeds the record limit.');
  }
  for (const [key, value] of Object.entries(document.records)) {
    if (
      !key ||
      key.length > 2048 ||
      !value ||
      typeof value !== 'object' ||
      !isDate(value.storedAt) ||
      !('value' in value)
    ) {
      throw new Error('Advisory snapshot contains an invalid record.');
    }
  }
  const payload: SnapshotPayload = {
    schemaVersion,
    generatedAt: document.generatedAt,
    records: document.records
  };
  const expected = Buffer.from(digest(payload), 'hex');
  const actual = Buffer.from(document.sha256, 'hex');
  if (!timingSafeEqual(expected, actual)) {
    throw new Error('Advisory snapshot integrity check failed.');
  }
  if (options.requireSignature && !document.signature) {
    throw new Error('Advisory snapshot signature is required.');
  }
  if (!document.signature) return { document, signatureStatus: 'unsigned' };
  if (
    document.signature.algorithm !== 'ed25519' ||
    !/^[A-Za-z0-9._-]{1,128}$/u.test(document.signature.keyId) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      document.signature.value
    )
  ) {
    throw new Error('Advisory snapshot signature metadata is invalid.');
  }
  if (!options.trustedPublicKeyPem) {
    if (options.requireSignature)
      throw new Error(
        'A trusted public key is required to verify the snapshot.'
      );
    return { document, signatureStatus: 'unverified' };
  }
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey(options.trustedPublicKeyPem);
  } catch {
    throw new Error('Advisory snapshot trusted public key is invalid.');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519')
    throw new Error('Advisory snapshot public key must use Ed25519.');
  const signature = Buffer.from(document.signature.value, 'base64');
  if (
    signature.length !== 64 ||
    !verifyBytes(
      null,
      signatureMessage(payload, document.sha256, document.signature.keyId),
      publicKey,
      signature
    )
  ) {
    throw new Error('Advisory snapshot signature verification failed.');
  }
  return { document, signatureStatus: 'verified' };
}

function parsedHasRecords(value: object): boolean {
  const records = (value as { records?: unknown }).records;
  return Boolean(
    records && typeof records === 'object' && !Array.isArray(records)
  );
}

async function readDocument(
  filePath: string,
  options: Pick<
    AdvisorySnapshotCacheOptions,
    'trustedPublicKeyPem' | 'requireSignature'
  >
): Promise<
  | { document: SnapshotDocument; signatureStatus: SnapshotSignatureStatus }
  | undefined
> {
  let named: Awaited<ReturnType<typeof lstat>>;
  try {
    named = await lstat(filePath);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return undefined;
    throw error;
  }
  if (named.isSymbolicLink() || !named.isFile()) {
    throw new Error('Advisory snapshot must be a regular, non-symlink file.');
  }
  if (named.size > maxSnapshotBytes) {
    throw new Error('Advisory snapshot exceeds the byte limit.');
  }
  const handle = await open(
    filePath,
    constants.O_RDONLY |
      noFollow |
      (process.platform === 'win32' ? 0 : constants.O_NONBLOCK)
  );
  try {
    const opened = await handle.stat();
    const after = await lstat(filePath);
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino
    ) {
      throw new Error('Advisory snapshot changed while it was being opened.');
    }
    return parseDocument(await handle.readFile('utf8'), options);
  } finally {
    await handle.close();
  }
}

/**
 * Bounded, integrity-checked local cache for OSV, EPSS and KEV data.
 * Writes merge under a process lock and replace the previous snapshot atomically.
 */
export class AdvisorySnapshotCache implements AnalyzerCache {
  readonly filePath: string;
  private _generatedAt?: string;
  private readonly base = new Map<string, StoredRecord>();
  private readonly pending = new Map<string, StoredRecord>();
  private readonly now: () => Date;
  private readonly signingKey?: KeyObject;
  private readonly signingKeyId?: string;
  private readonly trustedPublicKeyPem?: string;
  private _signatureStatus: SnapshotSignatureStatus;

  private constructor(
    filePath: string,
    document: SnapshotDocument | undefined,
    now: () => Date,
    options: AdvisorySnapshotCacheOptions,
    signatureStatus: SnapshotSignatureStatus
  ) {
    this.filePath = filePath;
    this._generatedAt = document?.generatedAt;
    this.now = now;
    this._signatureStatus = signatureStatus;
    this.trustedPublicKeyPem =
      options.trustedPublicKeyPem ??
      (options.signingPrivateKeyPem
        ? createPublicKey(createPrivateKey(options.signingPrivateKeyPem))
            .export({ type: 'spki', format: 'pem' })
            .toString()
        : undefined);
    if (options.signingPrivateKeyPem) {
      try {
        this.signingKey = createPrivateKey(options.signingPrivateKeyPem);
      } catch {
        throw new Error('Advisory snapshot signing private key is invalid.');
      }
      if (this.signingKey.asymmetricKeyType !== 'ed25519')
        throw new Error('Advisory snapshot signing key must use Ed25519.');
      if (!/^[A-Za-z0-9._-]{1,128}$/u.test(options.signingKeyId ?? ''))
        throw new Error(
          'A valid advisory snapshot signing key ID is required when signing.'
        );
      this.signingKeyId = options.signingKeyId;
    }
    for (const [key, value] of Object.entries(document?.records ?? {}))
      this.base.set(key, value);
  }

  get generatedAt(): string | undefined {
    return this._generatedAt;
  }

  get recordCount(): number {
    return (
      this.base.size +
      [...this.pending.keys()].filter((key) => !this.base.has(key)).length
    );
  }

  get snapshotAgeMs(): number | undefined {
    return this._generatedAt
      ? Math.max(0, this.now().getTime() - Date.parse(this._generatedAt))
      : undefined;
  }

  get signatureStatus(): SnapshotSignatureStatus {
    return this._signatureStatus;
  }

  static async open(
    requestedPath: string,
    options: AdvisorySnapshotCacheOptions = {}
  ): Promise<AdvisorySnapshotCache> {
    const absolute = path.resolve(requestedPath);
    const directory = await realpath(path.dirname(absolute));
    const directoryStat = await lstat(directory);
    if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
      throw new Error('Advisory snapshot parent must be a real directory.');
    }
    const filePath = path.join(directory, path.basename(absolute));
    if (options.signingPrivateKeyPem && options.trustedPublicKeyPem) {
      const signerPublic = createPublicKey(
        createPrivateKey(options.signingPrivateKeyPem)
      );
      const trustedPublic = createPublicKey(options.trustedPublicKeyPem);
      if (
        !signerPublic
          .export({ type: 'spki', format: 'der' })
          .equals(trustedPublic.export({ type: 'spki', format: 'der' }))
      )
        throw new Error(
          'Snapshot signing and trusted public keys must identify the same Ed25519 key.'
        );
    }
    const trustedPublicKeyPem =
      options.trustedPublicKeyPem ??
      (options.signingPrivateKeyPem
        ? createPublicKey(createPrivateKey(options.signingPrivateKeyPem))
            .export({ type: 'spki', format: 'pem' })
            .toString()
        : undefined);
    const parsed = await readDocument(filePath, {
      trustedPublicKeyPem,
      requireSignature: options.requireSignature
    });
    if (
      parsed?.document.signature &&
      options.signingKeyId &&
      parsed.document.signature.keyId !== options.signingKeyId
    )
      throw new Error('Advisory snapshot signing key ID does not match.');
    if (options.requireSignature && !parsed)
      throw new Error('Advisory snapshot signature is required.');
    return new AdvisorySnapshotCache(
      filePath,
      parsed?.document,
      options.now ?? (() => new Date()),
      options,
      parsed?.signatureStatus ?? 'unsigned'
    );
  }

  async get<T>(key: string): Promise<T | undefined> {
    const value = this.pending.get(key) ?? this.base.get(key);
    if (!value) return undefined;
    return JSON.parse(JSON.stringify(value.value)) as T;
  }

  async set<T>(key: string, value: T): Promise<void> {
    if (!key || key.length > 2048)
      throw new Error('Invalid snapshot cache key.');
    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(value);
    } catch {
      throw new Error('Advisory snapshot values must be JSON-serializable.');
    }
    if (
      serialized === undefined ||
      Buffer.byteLength(serialized) > maxSnapshotBytes
    ) {
      throw new Error(
        'Advisory snapshot value is missing or exceeds the byte limit.'
      );
    }
    if (
      !this.pending.has(key) &&
      !this.base.has(key) &&
      this.base.size + this.pending.size >= maxEntries
    )
      throw new Error('Advisory snapshot record limit reached.');
    this.pending.set(key, {
      storedAt: this.now().toISOString(),
      value: JSON.parse(serialized) as unknown
    });
  }

  ageMs(key: string, now = this.now().getTime()): number | undefined {
    const record = this.pending.get(key) ?? this.base.get(key);
    if (!record) return undefined;
    return Math.max(0, now - Date.parse(record.storedAt));
  }

  async flush(): Promise<void> {
    if (this.pending.size === 0) return;
    const directory = path.dirname(this.filePath);
    const directoryStat = await lstat(directory);
    if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
      throw new Error('Advisory snapshot parent changed to an unsafe path.');
    }
    const identity = { dev: directoryStat.dev, ino: directoryStat.ino };
    await withLocalStateLock(this.filePath, async (assertOwned) => {
      await assertDirectoryIdentity(directory, identity);
      const current = await readDocument(this.filePath, {
        trustedPublicKeyPem: this.trustedPublicKeyPem
      });
      if (current?.document.signature && !this.signingKey) {
        throw new Error(
          'Updating a signed advisory snapshot requires its signing key.'
        );
      }
      const records = new Map<string, StoredRecord>();
      const trustedCurrent =
        !this.signingKey || current?.signatureStatus === 'verified';
      if (trustedCurrent) {
        for (const [key, record] of Object.entries(
          current?.document.records ?? {}
        ))
          records.set(key, record);
        for (const [key, record] of this.base) {
          if (!records.has(key)) records.set(key, record);
        }
      }
      for (const [key, record] of this.pending) records.set(key, record);
      if (records.size > maxEntries)
        throw new Error('Advisory snapshot record limit reached.');

      const payload: SnapshotPayload = {
        schemaVersion,
        generatedAt: this.now().toISOString(),
        records: Object.fromEntries(
          [...records.entries()].sort(([left], [right]) =>
            left.localeCompare(right)
          )
        )
      };
      const document: SnapshotDocument = {
        ...payload,
        sha256: digest(payload)
      };
      if (this.signingKey && this.signingKeyId) {
        document.signature = {
          algorithm: 'ed25519',
          keyId: this.signingKeyId,
          value: signBytes(
            null,
            signatureMessage(payload, document.sha256, this.signingKeyId),
            this.signingKey
          ).toString('base64')
        };
      }
      const serialized = `${JSON.stringify(document)}\n`;
      if (Buffer.byteLength(serialized) > maxSnapshotBytes)
        throw new Error('Advisory snapshot exceeds the byte limit.');
      await writeAtomic(
        this.filePath,
        serialized,
        directory,
        identity,
        assertOwned
      );
      this.base.clear();
      for (const [key, record] of records) this.base.set(key, record);
      this.pending.clear();
      this._generatedAt = payload.generatedAt;
      this._signatureStatus = this.signingKey ? 'verified' : 'unsigned';
    });
  }
}

async function writeAtomic(
  filePath: string,
  serialized: string,
  directory: string,
  identity: DirectoryIdentity,
  assertOwned: LockGuard
): Promise<void> {
  const temporary = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await validateRegularFileIfPresent(filePath);
    await assertDirectoryIdentity(directory, identity);
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(serialized, 'utf8');
    if (process.platform !== 'win32') await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await assertOwned();
    await validateRegularFileIfPresent(filePath);
    await assertDirectoryIdentity(directory, identity);
    await rename(temporary, filePath);
    await syncDirectory(directory);
  } finally {
    await handle?.close();
    await rm(temporary, { force: true });
  }
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
