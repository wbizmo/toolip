import crypto from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import lockfile from 'proper-lockfile';

const staleMs = 30_000;
const updateMs = 10_000;

export type LockGuard = () => Promise<void>;

/** Serializes mutations across processes and validates the current lease before commit. */
export async function withLocalStateLock<T>(
  resourcePath: string,
  operation: (assertOwned: LockGuard) => Promise<T>,
  timeoutMs = 5_000,
  leaseStaleMs = staleMs
): Promise<T> {
  const resource = path.resolve(resourcePath);
  const lockPath = `${resource}.lock`;
  const ownerPath = `${lockPath}.owner`;
  const token = crypto.randomUUID();
  const temporaryOwnerPath = `${ownerPath}.${token}.tmp`;
  let compromised: Error | undefined;
  let markerInstalled = false;

  let release: () => Promise<void>;
  try {
    release = await lockfile.lock(resource, {
      realpath: false,
      stale: leaseStaleMs,
      update: Math.min(updateMs, Math.max(1_000, leaseStaleMs / 2)),
      retries: {
        retries: Math.max(1, Math.ceil(timeoutMs / 50)),
        factor: 1,
        minTimeout: 25,
        maxTimeout: 50,
        randomize: false
      },
      onCompromised(error) {
        compromised = error;
      }
    });
  } catch (error) {
    if (lockErrorCode(error) === 'ELOCKED') {
      throw localLockTimeout();
    }
    throw error;
  }

  let acquiredIdentity: { dev: number; ino: number } | undefined;
  try {
    const acquired = await lstat(lockPath);
    if (acquired.isSymbolicLink() || !acquired.isDirectory()) {
      throw localLockCompromised(
        new Error('Lock path is not a real directory.')
      );
    }
    acquiredIdentity = { dev: acquired.dev, ino: acquired.ino };
    await writeFile(temporaryOwnerPath, `${token}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx'
    });
    await rename(temporaryOwnerPath, ownerPath);
    markerInstalled = true;
    await restrictLockDirectory(lockPath);

    const assertOwned: LockGuard = async () => {
      if (compromised) throw localLockCompromised(compromised);
      if (!(await ownsLockDirectory(lockPath, acquiredIdentity))) {
        compromised = localLockCompromised(
          new Error('Lock directory identity changed.')
        );
        throw compromised;
      }
      let currentToken: string;
      try {
        currentToken = (await readFile(ownerPath, 'utf8')).trim();
      } catch (error) {
        compromised = localLockCompromised(error);
        throw compromised;
      }
      if (currentToken !== token) {
        compromised = localLockCompromised(
          new Error('Lock ownership token changed.')
        );
        throw compromised;
      }
      if (
        !(await lockfile.check(resource, {
          realpath: false,
          stale: leaseStaleMs
        }))
      ) {
        compromised = localLockCompromised(
          new Error('Lock lease is no longer active.')
        );
        throw compromised;
      }
      if (compromised) throw localLockCompromised(compromised);
    };

    await assertOwned();
    const result = await operation(assertOwned);
    await assertOwned();
    return result;
  } finally {
    await rm(temporaryOwnerPath, { force: true });
    if (
      !markerInstalled &&
      (await ownsLockDirectory(lockPath, acquiredIdentity))
    ) {
      await release();
    } else if (
      markerInstalled &&
      !compromised &&
      (await ownsMarker(ownerPath, token)) &&
      (await ownsLockDirectory(lockPath, acquiredIdentity))
    ) {
      await release();
    }
  }
}

/** Restricts lock-directory permissions after validating the opened directory identity. */
async function restrictLockDirectory(lockPath: string): Promise<void> {
  if (process.platform === 'win32') return;
  const handle = await open(
    lockPath,
    constants.O_RDONLY |
      (constants.O_DIRECTORY ?? 0) |
      (constants.O_NOFOLLOW ?? 0)
  );
  try {
    const opened = await handle.stat();
    const named = await lstat(lockPath);
    if (
      named.isSymbolicLink() ||
      !named.isDirectory() ||
      opened.dev !== named.dev ||
      opened.ino !== named.ino
    ) {
      throw localLockCompromised(
        new Error('Lock directory changed while opening.')
      );
    }
    await handle.chmod(0o700);
  } finally {
    await handle.close();
  }
}

/** Checks whether a lock path still names the directory acquired by this owner. */
async function ownsLockDirectory(
  lockPath: string,
  expected: { dev: number; ino: number } | undefined
): Promise<boolean> {
  if (!expected) return false;
  try {
    const value = await lstat(lockPath);
    return (
      value.isDirectory() &&
      !value.isSymbolicLink() &&
      value.dev === expected.dev &&
      value.ino === expected.ino
    );
  } catch {
    return false;
  }
}

/** Checks that the lock owner marker still contains this process's lease token. */
async function ownsMarker(ownerPath: string, token: string): Promise<boolean> {
  try {
    return (await readFile(ownerPath, 'utf8')).trim() === token;
  } catch {
    return false;
  }
}

/** Extracts a Node error code from an unknown thrown value. */
function lockErrorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

/** Creates the stable timeout error returned when a lease cannot be acquired. */
function localLockTimeout(): Error & { code: string } {
  return Object.assign(
    new Error(
      'Local state is busy. Try again after the active mutation completes.'
    ),
    { code: 'LOCAL_STATE_LOCK_TIMEOUT' }
  );
}

/** Creates the stable ownership-compromise error and preserves its cause. */
function localLockCompromised(cause: unknown): Error & { code: string } {
  const error = Object.assign(
    new Error('Local state lock ownership changed during a mutation.'),
    { code: 'LOCAL_STATE_LOCK_COMPROMISED' }
  );
  (error as Error & { cause?: unknown }).cause = cause;
  return error;
}
