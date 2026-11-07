import crypto from 'node:crypto';
import { open, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import type { HistoryEntry, HistoryStore } from './types.js';
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

/** Returns the canonical history file path for a project root. */
export function historyFilePath(root: string): string {
  return path.join(root, '.toolip', 'history.json');
}

/** Reads a validated versioned history file, treating only absence as an empty store. */
export async function readHistory(root: string): Promise<HistoryStore> {
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await validatePrivateDirectory(directory);
  if (!identity) return { schemaVersion, entries: [] };

  try {
    const raw = await openPrivateFile(filePath, maximumHistoryBytes);
    await assertDirectoryIdentity(directory, identity);
    return parseHistory(raw);
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
  maxEntries = defaultMaxEntries
): Promise<void> {
  await appendHistoryTransaction(root, () => entry, maxEntries);
}

/** Computes and appends an entry against the locked latest history snapshot. */
export async function appendHistoryTransaction(
  root: string,
  createEntry: (current: HistoryStore) => HistoryEntry | Promise<HistoryEntry>,
  maxEntries = defaultMaxEntries
): Promise<void> {
  const retentionLimit = normalizeRetentionLimit(maxEntries);
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await ensurePrivateDirectory(directory);

  await withLocalStateLock(
    filePath,
    async (assertOwned) => {
      await assertStoreDirectory(directory, identity);
      const current = await readHistory(root);
      const entry = await createEntry(current);
      if (current.entries.some((stored) => stored.id === entry.id)) return;

      const entries = [...current.entries, entry].slice(-retentionLimit);
      await writeHistoryAtomically(
        filePath,
        { schemaVersion, entries },
        directory,
        identity,
        assertOwned
      );
    },
    30_000
  );
}

/** Clears history as one serialized transaction; appends before clear are removed, later appends remain. */
export async function clearHistory(root: string): Promise<void> {
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await ensurePrivateDirectory(directory);

  await withLocalStateLock(
    filePath,
    async (assertOwned) => {
      await assertStoreDirectory(directory, identity);
      await writeHistoryAtomically(
        filePath,
        { schemaVersion, entries: [] },
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
