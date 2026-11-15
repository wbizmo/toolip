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
import { readBoundedUtf8File } from '../../core/bounded-file.js';

const schemaVersion = 1 as const;
const maxSnapshotBytes = 64 * 1024 * 1024;
const maxEntries = 200_000;
const maxPendingValueBytes = 16 * 1024 * 1024;
const maxPendingRecordBytes = maxPendingValueBytes + 8 * 1024;
const maxPendingBytes = 64 * 1024 * 1024;
const maxCanonicalDepth = 256;
const maxCanonicalNodes = 1_000_000;

type StoredRecord = { storedAt: string; value: unknown };
type SnapshotSource = {
  id: 'osv' | 'epss' | 'kev' | 'other';
  version: string;
  recordCount: number;
  capturedAt: string;
  sourceUpdatedAt: string;
};
export type SnapshotManifest = {
  format: 'toolip-advisory-bundle';
  version: 1;
  generatedAt: string;
  recordCount: number;
  ecosystems: string[];
  sources: SnapshotSource[];
};
type SnapshotPayload = {
  schemaVersion: typeof schemaVersion;
  generatedAt: string;
  manifest: SnapshotManifest;
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
  trustedKeyId?: string;
  signingPrivateKeyPem?: string;
  signingKeyId?: string;
  requireSignature?: boolean;
};

export type SnapshotSignatureStatus = 'unsigned' | 'unverified' | 'verified';

function canonicalJson(
  value: unknown,
  maximumBytes = maxSnapshotBytes
): string {
  const budget = { nodes: 0, bytes: 0 };
  const encodeString = (text: string): string => {
    if (text.length > Math.floor((maximumBytes - 2) / 6))
      throw new RangeError(
        'Advisory snapshot canonical data exceeds its byte limit.'
      );
    return JSON.stringify(text);
  };
  function* serialize(item: unknown, depth: number): Generator<string> {
    if (depth > maxCanonicalDepth)
      throw new RangeError(
        'Advisory snapshot canonical data exceeds its depth limit.'
      );
    if (++budget.nodes > maxCanonicalNodes)
      throw new RangeError(
        'Advisory snapshot canonical data exceeds its node limit.'
      );
    if (item === null) {
      yield 'null';
    } else if (typeof item === 'string') {
      yield encodeString(item);
    } else if (typeof item === 'boolean') {
      yield item ? 'true' : 'false';
    } else if (typeof item === 'number' && Number.isFinite(item)) {
      const encoded = JSON.stringify(item);
      if (encoded === undefined)
        throw new TypeError('Advisory snapshot contains a non-JSON number.');
      yield encoded;
    } else if (!item || typeof item !== 'object') {
      throw new TypeError('Advisory snapshot contains a non-JSON value.');
    } else if (Array.isArray(item)) {
      if (budget.nodes + item.length > maxCanonicalNodes)
        throw new RangeError(
          'Advisory snapshot canonical data exceeds its node limit.'
        );
      yield '[';
      for (let index = 0; index < item.length; index += 1) {
        if (index > 0) yield ',';
        yield* serialize(item[index], depth + 1);
      }
      yield ']';
    } else {
      let keyCount = 0;
      for (const key in item) {
        if (!Object.hasOwn(item, key)) continue;
        keyCount += 1;
        if (budget.nodes + keyCount > maxCanonicalNodes)
          throw new RangeError(
            'Advisory snapshot canonical data exceeds its node limit.'
          );
      }
      const record = item as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      budget.nodes += keys.length;
      yield '{';
      for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        if (key === undefined) continue;
        if (index > 0) yield ',';
        yield encodeString(key);
        yield ':';
        yield* serialize(record[key], depth + 1);
      }
      yield '}';
    }
  }
  const chunks: string[] = [];
  for (const text of serialize(value, 0)) {
    budget.bytes += Buffer.byteLength(text, 'utf8');
    if (budget.bytes > maximumBytes)
      throw new RangeError(
        'Advisory snapshot canonical data exceeds its byte limit.'
      );
    chunks.push(text);
  }
  return chunks.join('');
}

function digest(payload: SnapshotPayload): string {
  return createHash('sha256').update(canonicalJson(payload)).digest('hex');
}

function sourceId(key: string): SnapshotSource['id'] {
  if (key.startsWith('osv:v1:')) return 'osv';
  if (key.startsWith('exploit-intel:v1:epss:')) return 'epss';
  if (key === 'exploit-intel:v1:kev') return 'kev';
  return 'other';
}

function sourceTimestamp(key: string, record: StoredRecord): string {
  const value = record.value;
  if (key.startsWith('exploit-intel:v1:epss:')) {
    const asOf = (value as { asOf?: unknown } | null)?.asOf;
    const normalized = normalizeSourceDate(asOf);
    if (normalized) return normalized;
  }
  if (key === 'exploit-intel:v1:kev') {
    const asOf = (value as { asOf?: unknown } | null)?.asOf;
    const normalized = normalizeSourceDate(asOf);
    if (normalized) return normalized;
  }
  if (key.startsWith('osv:v1:')) {
    const vulnerabilities = (value as { vulnerabilities?: unknown } | null)
      ?.vulnerabilities;
    if (Array.isArray(vulnerabilities)) {
      let oldest: string | undefined;
      for (const item of vulnerabilities) {
        if (!item || typeof item !== 'object') continue;
        const modified = (item as { modified?: unknown }).modified;
        const normalized = normalizeSourceDate(modified);
        if (normalized && (oldest === undefined || normalized < oldest))
          oldest = normalized;
      }
      if (oldest) return oldest;
    }
  }
  return record.storedAt;
}

function sourceVersion(key: string, record: StoredRecord): string {
  if (key.startsWith('osv:v1:')) return 'v1';
  if (key.startsWith('exploit-intel:v1:epss:')) return 'v1';
  if (key === 'exploit-intel:v1:kev') {
    const version = (record.value as { catalogVersion?: unknown } | null)
      ?.catalogVersion;
    return typeof version === 'string' &&
      /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(version)
      ? version
      : 'unknown';
  }
  return 'unknown';
}

function normalizeSourceDate(value: unknown): string | undefined {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)))
    return undefined;
  return new Date(value).toISOString();
}

function buildManifest(
  records: Record<string, StoredRecord>,
  generatedAt: string
): SnapshotManifest {
  const bySource = new Map<
    string,
    {
      id: SnapshotSource['id'];
      version: string;
      count: number;
      capturedAt: string;
      sourceUpdatedAt: string;
    }
  >();
  const ecosystems = new Set<string>();
  let recordCount = 0;
  for (const key in records) {
    if (!Object.hasOwn(records, key)) continue;
    recordCount += 1;
    const record = records[key];
    if (!record) continue;
    const id = sourceId(key);
    const version = sourceVersion(key, record);
    const sourceKey = `${id}\0${version}`;
    const current = bySource.get(sourceKey) ?? {
      id,
      version,
      count: 0,
      capturedAt: record.storedAt,
      sourceUpdatedAt: sourceTimestamp(key, record)
    };
    current.count++;
    if (record.storedAt < current.capturedAt)
      current.capturedAt = record.storedAt;
    const sourceUpdatedAt = sourceTimestamp(key, record);
    if (sourceUpdatedAt < current.sourceUpdatedAt)
      current.sourceUpdatedAt = sourceUpdatedAt;
    bySource.set(sourceKey, current);
    if (id === 'osv') {
      const ecosystem = key.slice('osv:v1:'.length).split(':', 1)[0];
      if (ecosystem) ecosystems.add(ecosystem);
    }
  }
  const sources = [...bySource.values()]
    .sort(
      (left, right) =>
        left.id.localeCompare(right.id) ||
        left.version.localeCompare(right.version)
    )
    .map((source) => ({
      id: source.id,
      version: source.version,
      recordCount: source.count,
      capturedAt: source.capturedAt,
      sourceUpdatedAt: source.sourceUpdatedAt
    }));
  return {
    format: 'toolip-advisory-bundle',
    version: 1,
    generatedAt,
    recordCount,
    ecosystems: [...ecosystems].sort((left, right) =>
      left.localeCompare(right)
    ),
    sources
  };
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
    'trustedPublicKeyPem' | 'trustedKeyId' | 'requireSignature' | 'now'
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
  const nowMs = (options.now ?? (() => new Date()))().getTime();
  const futureLimit = nowMs + 5 * 60 * 1000;
  if (Date.parse(document.generatedAt) > futureLimit)
    throw new Error('Advisory snapshot generation time is in the future.');
  const allowedKeys = new Set([
    'schemaVersion',
    'generatedAt',
    'manifest',
    'records',
    'sha256',
    'signature'
  ]);
  if (Object.keys(document).some((key) => !allowedKeys.has(key)))
    throw new Error('Advisory snapshot contains unsupported top-level fields.');
  let recordCount = 0;
  for (const key in document.records) {
    if (!Object.hasOwn(document.records, key)) continue;
    recordCount += 1;
    if (recordCount > maxEntries)
      throw new Error('Advisory snapshot exceeds the record limit.');
    const value = document.records[key];
    if (
      !key ||
      key.length > 2048 ||
      !value ||
      typeof value !== 'object' ||
      !isDate(value.storedAt) ||
      Date.parse(value.storedAt) > futureLimit ||
      !('value' in value)
    ) {
      throw new Error('Advisory snapshot contains an invalid record.');
    }
  }
  const payload: SnapshotPayload = {
    schemaVersion,
    generatedAt: document.generatedAt,
    manifest: document.manifest,
    records: document.records
  };
  if (
    !document.manifest ||
    canonicalJson(document.manifest) !==
      canonicalJson(buildManifest(document.records, document.generatedAt))
  )
    throw new Error('Advisory snapshot manifest does not match its records.');
  if (
    document.manifest.sources.some(
      (source) => Date.parse(source.sourceUpdatedAt) > futureLimit
    )
  )
    throw new Error('Advisory snapshot source timestamp is in the future.');
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
  if (
    options.trustedKeyId &&
    document.signature.keyId !== options.trustedKeyId
  ) {
    throw new Error('Advisory snapshot signing key ID does not match.');
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
    'trustedPublicKeyPem' | 'trustedKeyId' | 'requireSignature' | 'now'
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
  return parseDocument(
    await readBoundedUtf8File(filePath, maxSnapshotBytes),
    options
  );
}

/**
 * Bounded, integrity-checked local cache for OSV, EPSS and KEV data.
 * Writes merge under a process lock and replace the previous snapshot atomically.
 */
export class AdvisorySnapshotCache implements AnalyzerCache {
  readonly filePath: string;
  private _generatedAt?: string;
  private _manifest?: SnapshotManifest;
  private readonly base = new Map<string, StoredRecord>();
  private readonly pending = new Map<string, StoredRecord>();
  private readonly pendingBytesByKey = new Map<string, number>();
  private pendingBytes = 0;
  private readonly now: () => Date;
  private readonly signingKey?: KeyObject;
  private readonly signingKeyId?: string;
  private readonly trustedPublicKeyPem?: string;
  private readonly trustedKeyId?: string;
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
    this._manifest = document?.manifest;
    this.now = now;
    this._signatureStatus = signatureStatus;
    this.trustedPublicKeyPem =
      options.trustedPublicKeyPem ??
      (options.signingPrivateKeyPem
        ? createPublicKey(createPrivateKey(options.signingPrivateKeyPem))
            .export({ type: 'spki', format: 'pem' })
            .toString()
        : undefined);
    this.trustedKeyId = options.trustedKeyId ?? options.signingKeyId;
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
    const persistedRecords = document?.records ?? {};
    for (const key in persistedRecords) {
      if (Object.hasOwn(persistedRecords, key))
        this.base.set(key, persistedRecords[key] as StoredRecord);
    }
  }

  get generatedAt(): string | undefined {
    return this._generatedAt;
  }

  get manifest(): SnapshotManifest | undefined {
    return this._manifest ? structuredClone(this._manifest) : undefined;
  }

  get recordCount(): number {
    let count = this.base.size;
    for (const key of this.pending.keys()) if (!this.base.has(key)) count += 1;
    return count;
  }

  get snapshotAgeMs(): number | undefined {
    return this._generatedAt
      ? Math.max(0, this.now().getTime() - Date.parse(this._generatedAt))
      : undefined;
  }

  /** Age of the oldest captured source record, or undefined for an empty bundle. */
  get oldestSourceAgeMs(): number | undefined {
    const sources = this._manifest?.sources;
    if (!sources || sources.length === 0) return undefined;
    let oldest = Number.POSITIVE_INFINITY;
    for (const source of sources)
      oldest = Math.min(oldest, Date.parse(source.capturedAt));
    return Number.isFinite(oldest)
      ? Math.max(0, this.now().getTime() - oldest)
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
    const now = options.now ?? (() => new Date());
    const parsed = await readDocument(filePath, {
      trustedPublicKeyPem,
      trustedKeyId: options.trustedKeyId ?? options.signingKeyId,
      requireSignature: options.requireSignature,
      now
    });
    if (options.requireSignature && !parsed)
      throw new Error('Advisory snapshot signature is required.');
    return new AdvisorySnapshotCache(
      filePath,
      parsed?.document,
      now,
      options,
      parsed?.signatureStatus ?? 'unsigned'
    );
  }

  async get<T>(key: string): Promise<T | undefined> {
    const value = this.pending.get(key) ?? this.base.get(key);
    if (!value) return undefined;
    return JSON.parse(canonicalJson(value.value, maxPendingValueBytes)) as T;
  }

  async set<T>(key: string, value: T): Promise<void> {
    if (!key || key.length > 2048)
      throw new Error('Invalid snapshot cache key.');
    let serialized: string | undefined;
    try {
      serialized = canonicalJson(value, maxPendingValueBytes);
    } catch {
      throw new Error(
        'Advisory snapshot values must be bounded JSON-serializable data.'
      );
    }
    if (serialized === undefined)
      throw new Error(
        'Advisory snapshot value is missing or not JSON-serializable.'
      );
    const entryBytes =
      Buffer.byteLength(serialized, 'utf8') + Buffer.byteLength(key, 'utf8');
    if (entryBytes > maxPendingRecordBytes)
      throw new Error('Advisory snapshot record exceeds the 16 MiB limit.');
    if (
      !this.pending.has(key) &&
      !this.base.has(key) &&
      this.base.size + this.pending.size >= maxEntries
    )
      throw new Error('Advisory snapshot record limit reached.');
    const previousBytes = this.pendingBytesByKey.get(key) ?? 0;
    if (this.pendingBytes - previousBytes + entryBytes > maxPendingBytes)
      throw new Error(
        'Advisory snapshot pending cache exceeds the 64 MiB limit.'
      );
    this.pendingBytes += entryBytes - previousBytes;
    this.pendingBytesByKey.set(key, entryBytes);
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
        trustedPublicKeyPem: this.trustedPublicKeyPem,
        trustedKeyId: this.trustedKeyId,
        now: this.now
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
        const currentRecords = current?.document.records ?? {};
        for (const key in currentRecords) {
          if (Object.hasOwn(currentRecords, key))
            records.set(key, currentRecords[key] as StoredRecord);
        }
        for (const [key, record] of this.base) {
          if (!records.has(key)) records.set(key, record);
        }
      }
      for (const [key, record] of this.pending) records.set(key, record);
      if (records.size > maxEntries)
        throw new Error('Advisory snapshot record limit reached.');

      const generatedAt = this.now().toISOString();
      const sortedKeys = [...records.keys()].sort((left, right) =>
        left.localeCompare(right)
      );
      const sortedRecords = Object.create(null) as Record<string, StoredRecord>;
      for (const key of sortedKeys) {
        const record = records.get(key);
        if (record) sortedRecords[key] = record;
      }
      const payload: SnapshotPayload = {
        schemaVersion,
        generatedAt,
        manifest: buildManifest(sortedRecords, generatedAt),
        records: sortedRecords
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
      const serialized = `${canonicalJson(document, maxSnapshotBytes - 1)}\n`;
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
      this.pendingBytesByKey.clear();
      this.pendingBytes = 0;
      this._generatedAt = payload.generatedAt;
      this._manifest = payload.manifest;
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
