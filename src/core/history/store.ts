import crypto, { createHmac, timingSafeEqual } from 'node:crypto';
import { open, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import type { HistoryEntry, HistoryStore } from './types.js';
import type { HistoryIntegrity } from './types.js';
import { canonicalJson } from '../canonical-json.js';
import {
  assertDirectoryIdentity,
  ensurePrivateDirectory,
  openPrivateFile,
  syncDirectory,
  validatePrivateDirectory,
  validateRegularFileIfPresent,
  type DirectoryIdentity
} from '../local-state-fs.js';
import { withLocalStateLock, type LockGuard } from '../local-lock.js';

const schemaVersion = '1.0' as const;
const defaultMaxEntries = 500;
const maximumHistoryEntries = 5_000;
const maximumHistoryBytes = 32 * 1024 * 1024;

export type HistoryIntegrityOptions = {
  key: Uint8Array;
  keyId: string;
  requireIntegrity?: boolean;
};

/** Returns the canonical history file path for a project root. */
export function historyFilePath(root: string): string {
  return path.join(root, '.toolip', 'history.json');
}

/** Reads a validated versioned history file, treating only absence as an empty store. */
export async function readHistory(
  root: string,
  integrityOptions?: HistoryIntegrityOptions
): Promise<HistoryStore> {
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await validatePrivateDirectory(directory);
  if (!identity) return { schemaVersion, entries: [] };

  try {
    const raw = await openPrivateFile(filePath, maximumHistoryBytes);
    await assertDirectoryIdentity(directory, identity);
    return verifyHistoryStore(parseHistory(raw), integrityOptions);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') {
      return { schemaVersion, entries: [] };
    }
    throw error;
  }
}

/** Appends under a cross-process lease and atomically commits a unique temp file. */
export async function appendHistory(
  root: string,
  entry: HistoryEntry,
  maxEntries = defaultMaxEntries,
  integrityOptions?: HistoryIntegrityOptions
): Promise<void> {
  await appendHistoryTransaction(
    root,
    () => entry,
    maxEntries,
    integrityOptions
  );
}

/** Computes and appends an entry against the locked latest history snapshot. */
export async function appendHistoryTransaction(
  root: string,
  createEntry: (current: HistoryStore) => HistoryEntry | Promise<HistoryEntry>,
  maxEntries = defaultMaxEntries,
  integrityOptions?: HistoryIntegrityOptions
): Promise<void> {
  validateIntegrityOptions(integrityOptions);
  const retentionLimit = normalizeRetentionLimit(maxEntries);
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await ensurePrivateDirectory(directory);

  await withLocalStateLock(
    filePath,
    async (assertOwned) => {
      await assertStoreDirectory(directory, identity);
      const current = await readHistory(
        root,
        integrityOptions
          ? { ...integrityOptions, requireIntegrity: false }
          : undefined
      );
      const entry = await createEntry(current);
      if (current.entries.some((stored) => stored.id === entry.id)) return;

      const entries = [...current.entries, entry].slice(-retentionLimit);
      const integrity = integrityOptions
        ? appendIntegrity(current, entry, entries, integrityOptions)
        : undefined;
      await writeHistoryAtomically(
        filePath,
        { schemaVersion, entries, ...(integrity ? { integrity } : {}) },
        directory,
        identity,
        assertOwned
      );
    },
    30_000
  );
}

/** Clears history as one serialized transaction; appends before clear are removed, later appends remain. */
export async function clearHistory(
  root: string,
  integrityOptions?: HistoryIntegrityOptions
): Promise<void> {
  validateIntegrityOptions(integrityOptions);
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await ensurePrivateDirectory(directory);

  await withLocalStateLock(
    filePath,
    async (assertOwned) => {
      await assertStoreDirectory(directory, identity);
      const current = await readHistory(
        root,
        integrityOptions
          ? { ...integrityOptions, requireIntegrity: false }
          : undefined
      );
      await writeHistoryAtomically(
        filePath,
        {
          schemaVersion,
          entries: [],
          ...(integrityOptions
            ? { integrity: emptyIntegrity(integrityOptions.keyId) }
            : current.integrity
              ? { integrity: current.integrity }
              : {})
        },
        directory,
        identity,
        assertOwned
      );
    },
    30_000
  );
}

/** Re-signs a verified store with a rotated local key without changing entries. */
export async function rotateHistoryIntegrityKey(
  root: string,
  currentOptions: HistoryIntegrityOptions,
  nextOptions: HistoryIntegrityOptions
): Promise<void> {
  validateIntegrityOptions(currentOptions);
  validateIntegrityOptions(nextOptions);
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await ensurePrivateDirectory(directory);
  await withLocalStateLock(
    filePath,
    async (assertOwned) => {
      await assertStoreDirectory(directory, identity);
      const current = await readHistory(root, currentOptions);
      const integrity = signAllEntries(current.entries, nextOptions);
      await writeHistoryAtomically(
        filePath,
        { schemaVersion, entries: current.entries, integrity },
        directory,
        identity,
        assertOwned
      );
    },
    30_000
  );
}

/** Adds an authenticated chain to a legacy unsigned history after review. */
export async function protectHistoryIntegrity(
  root: string,
  options: HistoryIntegrityOptions
): Promise<void> {
  validateIntegrityOptions(options);
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await ensurePrivateDirectory(directory);
  await withLocalStateLock(
    filePath,
    async (assertOwned) => {
      await assertStoreDirectory(directory, identity);
      const current = await readHistory(root, options);
      if (current.integrity)
        throw new Error('Toolip history already has an integrity chain.');
      await writeHistoryAtomically(
        filePath,
        {
          schemaVersion,
          entries: current.entries,
          integrity: signAllEntries(current.entries, options)
        },
        directory,
        identity,
        assertOwned
      );
    },
    30_000
  );
}

/** Parses and validates the supported history schema. */
function parseHistory(raw: string): HistoryStore {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Toolip history file is corrupt JSON.');
  }

  if (
    !parsed ||
    typeof parsed !== 'object' ||
    !('schemaVersion' in parsed) ||
    parsed.schemaVersion !== schemaVersion ||
    !('entries' in parsed) ||
    !Array.isArray(parsed.entries)
  ) {
    throw new Error('Unsupported Toolip history schema.');
  }
  if (parsed.entries.length > maximumHistoryEntries)
    throw new Error('Toolip history exceeds its entry budget.');

  if ('integrity' in parsed && parsed.integrity !== undefined)
    validateIntegrityShape(parsed.integrity, parsed.entries.length);

  return parsed as HistoryStore;
}

function normalizeRetentionLimit(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximumHistoryEntries
  )
    throw new RangeError(
      `History retention must be between 1 and ${maximumHistoryEntries} entries.`
    );
  return value;
}

function verifyHistoryStore(
  store: HistoryStore,
  options?: HistoryIntegrityOptions
): HistoryStore {
  if (!store.integrity) {
    if (options?.requireIntegrity && store.entries.length > 0)
      throw new Error('Toolip history is unsigned and cannot be trusted.');
    return store;
  }
  if (!options)
    throw new Error(
      'Toolip history integrity key is required to verify this file.'
    );
  validateIntegrityOptions(options);
  if (store.integrity.keyId !== options.keyId)
    throw new Error('Toolip history integrity key ID does not match.');

  let previousMac = store.integrity.anchorMac;
  let sequence = store.integrity.anchorSequence;
  for (let index = 0; index < store.entries.length; index += 1) {
    const entry = store.entries[index];
    const record = store.integrity.records[index];
    if (!entry || !record || record.sequence !== sequence + 1)
      throw new Error('Toolip history integrity chain has a sequence gap.');
    const expected = historyMac(
      entry,
      record.sequence,
      previousMac,
      options.key,
      options.keyId
    );
    const expectedBytes = Buffer.from(expected, 'hex');
    const actualBytes = Buffer.from(record.mac, 'hex');
    if (
      expectedBytes.length !== actualBytes.length ||
      !timingSafeEqual(expectedBytes, actualBytes)
    )
      throw new Error('Toolip history integrity verification failed.');
    previousMac = record.mac;
    sequence = record.sequence;
  }
  if (store.integrity.headMac !== previousMac)
    throw new Error('Toolip history head integrity verification failed.');
  return store;
}

function appendIntegrity(
  current: HistoryStore,
  entry: HistoryEntry,
  retainedEntries: HistoryEntry[],
  options: HistoryIntegrityOptions
): HistoryIntegrity {
  if (!current.integrity) return signAllEntries(retainedEntries, options);

  const previous = current.integrity;
  const nextSequence = previous.anchorSequence + previous.records.length + 1;
  const nextMac = historyMac(
    entry,
    nextSequence,
    previous.headMac,
    options.key,
    options.keyId
  );
  const records = [
    ...previous.records,
    { sequence: nextSequence, mac: nextMac }
  ];
  const dropCount = records.length - retainedEntries.length;
  let anchorSequence = previous.anchorSequence;
  let anchorMac = previous.anchorMac;
  if (dropCount > 0) {
    const anchor = records[dropCount - 1];
    if (!anchor) throw new Error('Toolip history integrity anchor is invalid.');
    anchorSequence = anchor.sequence;
    anchorMac = anchor.mac;
  }
  const retainedRecords = records.slice(dropCount);
  return {
    algorithm: 'HMAC-SHA-256',
    keyId: options.keyId,
    anchorSequence,
    anchorMac,
    records: retainedRecords,
    headMac: retainedRecords.at(-1)?.mac ?? anchorMac
  };
}

function signAllEntries(
  entries: HistoryEntry[],
  options: HistoryIntegrityOptions
): HistoryIntegrity {
  const records: HistoryIntegrity['records'] = [];
  let previousMac: string | null = null;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (!entry) throw new Error('Toolip history contains a missing entry.');
    const sequence = index + 1;
    const mac = historyMac(
      entry,
      sequence,
      previousMac,
      options.key,
      options.keyId
    );
    records.push({ sequence, mac });
    previousMac = mac;
  }
  return {
    algorithm: 'HMAC-SHA-256',
    keyId: options.keyId,
    anchorSequence: 0,
    anchorMac: null,
    records,
    headMac: previousMac
  };
}

function emptyIntegrity(keyId: string): HistoryIntegrity {
  return {
    algorithm: 'HMAC-SHA-256',
    keyId,
    anchorSequence: 0,
    anchorMac: null,
    records: [],
    headMac: null
  };
}

function historyMac(
  entry: HistoryEntry,
  sequence: number,
  previousMac: string | null,
  key: Uint8Array,
  keyId: string
): string {
  const payload = canonicalJson({
    schema: 'toolip-history-hmac-v1',
    keyId,
    sequence,
    previousMac,
    entry
  });
  return createHmac('sha256', key).update(payload, 'utf8').digest('hex');
}

function validateIntegrityOptions(options?: HistoryIntegrityOptions): void {
  if (!options) return;
  if (
    !(options.key instanceof Uint8Array) ||
    options.key.byteLength < 32 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(options.keyId)
  )
    throw new Error('Toolip history integrity key options are invalid.');
}

function validateIntegrityShape(
  value: unknown,
  entryCount: number
): asserts value is HistoryIntegrity {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Toolip history integrity metadata is malformed.');
  const integrity = value as Partial<HistoryIntegrity>;
  if (
    integrity.algorithm !== 'HMAC-SHA-256' ||
    typeof integrity.keyId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(integrity.keyId) ||
    !Number.isSafeInteger(integrity.anchorSequence) ||
    (integrity.anchorSequence ?? -1) < 0 ||
    !Array.isArray(integrity.records) ||
    integrity.records.length !== entryCount ||
    (integrity.anchorMac !== null &&
      (typeof integrity.anchorMac !== 'string' ||
        !/^[a-f0-9]{64}$/u.test(integrity.anchorMac))) ||
    (integrity.headMac !== null &&
      (typeof integrity.headMac !== 'string' ||
        !/^[a-f0-9]{64}$/u.test(integrity.headMac)))
  )
    throw new Error('Toolip history integrity metadata is malformed.');
  for (const record of integrity.records) {
    if (
      !record ||
      !Number.isSafeInteger(record.sequence) ||
      record.sequence < 1 ||
      typeof record.mac !== 'string' ||
      !/^[a-f0-9]{64}$/u.test(record.mac)
    )
      throw new Error('Toolip history integrity record is malformed.');
  }
}

/** Writes a history snapshot through a private same-directory temporary file. */
async function writeHistoryAtomically(
  filePath: string,
  store: HistoryStore,
  directory: string,
  identity: DirectoryIdentity,
  assertOwned: LockGuard
): Promise<void> {
  const temporary = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const serialized = `${JSON.stringify(store, null, 2)}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > maximumHistoryBytes)
    throw new Error('Toolip history exceeds its byte budget.');
  let handle: Awaited<ReturnType<typeof open>> | undefined;

  try {
    await validateRegularFileIfPresent(filePath);
    await assertStoreDirectory(directory, identity);
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(serialized, 'utf8');
    if (process.platform !== 'win32') await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;

    await assertOwned();
    await assertStoreDirectory(directory, identity);
    await validateRegularFileIfPresent(filePath);
    await rename(temporary, filePath);
    await syncDirectory(directory);
    await assertStoreDirectory(directory, identity);
  } finally {
    await handle?.close();
    await rm(temporary, { force: true });
  }
}

/** Confirms that the store directory still has its validated filesystem identity. */
async function assertStoreDirectory(
  directory: string,
  identity: DirectoryIdentity
): Promise<void> {
  await assertDirectoryIdentity(directory, identity);
}

/** Returns a Node filesystem error code when one is present. */
function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
