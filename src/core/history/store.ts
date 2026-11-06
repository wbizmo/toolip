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
    const raw = await openPrivateFile(filePath);
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
  maxEntries = 500
): Promise<void> {
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const identity = await ensurePrivateDirectory(directory);

  await withLocalStateLock(
    filePath,
    async (assertOwned) => {
      await assertStoreDirectory(directory, identity);
      const current = await readHistory(root);
      if (current.entries.some((stored) => stored.id === entry.id)) return;

      const entries = [...current.entries, entry].slice(
        -Math.max(1, Math.floor(maxEntries))
      );
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

  return parsed as HistoryStore;
}

async function writeHistoryAtomically(
  filePath: string,
  store: HistoryStore,
  directory: string,
  identity: DirectoryIdentity,
  assertOwned: LockGuard
): Promise<void> {
  const temporary = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const serialized = `${JSON.stringify(store, null, 2)}\n`;
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

async function assertStoreDirectory(
  directory: string,
  identity: DirectoryIdentity
): Promise<void> {
  await assertDirectoryIdentity(directory, identity);
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
