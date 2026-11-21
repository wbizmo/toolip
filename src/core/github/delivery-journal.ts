import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import {
  assertDirectoryIdentity,
  ensurePrivateDirectory,
  syncDirectory,
  validateRegularFileIfPresent,
  type DirectoryIdentity
} from '../local-state-fs.js';
import { withLocalStateLock, type LockGuard } from '../local-lock.js';

const version = 1;
const maximumStateBytes = 16 * 1024 * 1024;
const maximumInstallations = 10_000;
const maximumDeliveries = 100_000;

type DeliveryState = {
  version: 1;
  deliveries: Record<string, number>;
  suspendedInstallations: number[];
};

export type DeliveryJournalSnapshot = Readonly<{
  suspendedInstallations: readonly number[];
}>;

function digestDeliveryId(deliveryId: string): string {
  return createHash('sha256').update(deliveryId).digest('hex');
}

function parseState(text: string): DeliveryState {
  if (Buffer.byteLength(text, 'utf8') > maximumStateBytes)
    throw new Error('GitHub App delivery state exceeds its byte limit.');
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('GitHub App delivery state is malformed JSON.');
  }
  if (
    !value ||
    typeof value !== 'object' ||
    (value as Record<string, unknown>).version !== version ||
    !(value as Record<string, unknown>).deliveries ||
    typeof (value as Record<string, unknown>).deliveries !== 'object' ||
    Array.isArray((value as Record<string, unknown>).deliveries) ||
    !Array.isArray((value as Record<string, unknown>).suspendedInstallations)
  )
    throw new Error('GitHub App delivery state schema is unsupported.');
  const record = value as Record<string, unknown>;
  const deliveries = record.deliveries as Record<string, unknown>;
  const keys = Object.keys(deliveries);
  if (
    keys.length > maximumDeliveries ||
    keys.some(
      (key) =>
        !/^[a-f0-9]{64}$/u.test(key) ||
        !Number.isSafeInteger(deliveries[key]) ||
        (deliveries[key] as number) <= 0
    ) ||
    (record.suspendedInstallations as unknown[]).length >
      maximumInstallations ||
    (record.suspendedInstallations as unknown[]).some(
      (id) => !Number.isSafeInteger(id) || (id as number) <= 0
    )
  )
    throw new Error('GitHub App delivery state contains invalid entries.');
  return {
    version,
    deliveries: deliveries as Record<string, number>,
    suspendedInstallations: [
      ...new Set(record.suspendedInstallations as number[])
    ].sort((left, right) => left - right)
  };
}

async function readState(filePath: string): Promise<DeliveryState> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const before = await lstat(filePath, { bigint: true });
    if (
      before.isSymbolicLink() ||
      !before.isFile() ||
      before.size > BigInt(maximumStateBytes)
    )
      throw new Error(
        'GitHub App delivery state must be a bounded regular file.'
      );
    const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
    const nonBlocking = process.platform === 'win32' ? 0 : constants.O_NONBLOCK;
    handle = await open(filePath, constants.O_RDONLY | noFollow | nonBlocking);
    let opened = await handle.stat({ bigint: true });
    const named = await lstat(filePath, { bigint: true });
    if (
      !opened.isFile() ||
      named.isSymbolicLink() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.dev !== named.dev ||
      opened.ino !== named.ino ||
      opened.size !== before.size ||
      opened.size > BigInt(maximumStateBytes) ||
      (typeof process.geteuid === 'function' &&
        opened.uid !== BigInt(process.geteuid()))
    )
      throw new Error('GitHub App delivery state changed while opening.');
    if (process.platform !== 'win32') {
      await handle.chmod(0o600);
      opened = await handle.stat({ bigint: true });
    }
    const bytes = Buffer.alloc(Number(opened.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        null
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
      if (offset > maximumStateBytes)
        throw new Error('GitHub App delivery state exceeds its byte limit.');
    }
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(filePath, { bigint: true });
    if (
      offset !== Number(opened.size) ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      afterPath.isSymbolicLink() ||
      afterPath.dev !== opened.dev ||
      afterPath.ino !== opened.ino
    )
      throw new Error('GitHub App delivery state changed while reading.');
    return parseState(
      new TextDecoder('utf-8', { fatal: true }).decode(
        bytes.subarray(0, offset)
      )
    );
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'code' in error &&
      (error as { code?: unknown }).code === 'ENOENT'
    )
      return { version, deliveries: {}, suspendedInstallations: [] };
    throw error;
  } finally {
    await handle?.close();
  }
}

async function writeState(
  filePath: string,
  state: DeliveryState,
  directory: string,
  identity: DirectoryIdentity,
  assertOwned: LockGuard
): Promise<void> {
  const temporary = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  const serialized = `${JSON.stringify(state)}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > maximumStateBytes)
    throw new Error('GitHub App delivery state exceeds its byte limit.');
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
    await assertDirectoryIdentity(directory, identity);
    await validateRegularFileIfPresent(filePath);
    await rename(temporary, filePath);
    await syncDirectory(directory);
    await assertDirectoryIdentity(directory, identity);
  } finally {
    await handle?.close();
    await rm(temporary, { force: true });
  }
}

/** A private, bounded, cross-process replay and installation-state journal. */
export class GitHubAppDeliveryJournal {
  private readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
  }

  async snapshot(): Promise<DeliveryJournalSnapshot> {
    const directory = path.dirname(this.filePath);
    const identity = await ensurePrivateDirectory(directory);
    return withLocalStateLock(
      this.filePath,
      async (assertOwned) => {
        await assertDirectoryIdentity(directory, identity);
        const state = await readState(this.filePath);
        await assertOwned();
        return Object.freeze({
          suspendedInstallations: Object.freeze([
            ...state.suspendedInstallations
          ])
        });
      },
      10_000
    );
  }

  /** Atomically claims a delivery and applies an installation state transition. */
  async claim(
    deliveryId: string,
    options: {
      now: number;
      ttlMs: number;
      limit: number;
      installation?: { id: number; suspended: boolean };
    }
  ): Promise<boolean> {
    if (
      !Number.isFinite(options.now) ||
      !Number.isSafeInteger(options.ttlMs) ||
      options.ttlMs < 1 ||
      !Number.isSafeInteger(options.limit) ||
      options.limit < 1 ||
      (options.installation &&
        (!Number.isSafeInteger(options.installation.id) ||
          options.installation.id < 1))
    )
      throw new RangeError('GitHub App delivery journal limits are invalid.');
    const directory = path.dirname(this.filePath);
    const identity = await ensurePrivateDirectory(directory);
    return withLocalStateLock(
      this.filePath,
      async (assertOwned) => {
        await assertDirectoryIdentity(directory, identity);
        const state = await readState(this.filePath);
        for (const [key, expiresAt] of Object.entries(state.deliveries))
          if (expiresAt <= options.now) delete state.deliveries[key];
        const key = digestDeliveryId(deliveryId);
        if (Object.hasOwn(state.deliveries, key)) return false;
        if (Object.keys(state.deliveries).length >= options.limit)
          throw new Error('GitHub App delivery journal is full.');
        state.deliveries[key] = options.now + options.ttlMs;
        if (options.installation) {
          const installations = new Set(state.suspendedInstallations);
          if (options.installation.suspended)
            installations.add(options.installation.id);
          else installations.delete(options.installation.id);
          if (installations.size > maximumInstallations)
            throw new Error(
              'GitHub App installation state exceeds its entry limit.'
            );
          state.suspendedInstallations = [...installations].sort(
            (left, right) => left - right
          );
        }
        await writeState(
          this.filePath,
          state,
          directory,
          identity,
          assertOwned
        );
        return true;
      },
      10_000
    );
  }
}
