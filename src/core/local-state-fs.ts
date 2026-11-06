import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import path from 'node:path';

export type DirectoryIdentity = {
  dev: number;
  ino: number;
};

const noFollow = constants.O_NOFOLLOW ?? 0;
const directoryOnly = constants.O_DIRECTORY ?? 0;

/** Creates or repairs a private, user-owned local-state directory without following its final symlink. */
export async function ensurePrivateDirectory(
  directoryPath: string
): Promise<DirectoryIdentity> {
  const resolved = path.resolve(directoryPath);
  await mkdir(resolved, { recursive: true, mode: 0o700 });

  const identity = await validatePrivateDirectory(resolved);
  if (!identity) {
    throw localStatePathError('Local state directory does not exist.');
  }
  return identity;
}

/** Validates an existing private directory without creating it. */
export async function validatePrivateDirectory(
  directoryPath: string
): Promise<DirectoryIdentity | undefined> {
  const resolved = path.resolve(directoryPath);

  let named: Awaited<ReturnType<typeof lstat>>;
  try {
    named = await lstat(resolved);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return undefined;
    throw error;
  }
  if (named.isSymbolicLink() || !named.isDirectory()) {
    throw localStatePathError(
      'Local state directory must be a real directory.'
    );
  }

  const canonical = await realpath(resolved);
  if (!samePath(canonical, resolved)) {
    throw localStatePathError(
      'Local state directory cannot be reached through a symlink.'
    );
  }

  if (process.platform === 'win32') {
    return identity(named);
  }

  assertCurrentOwner(named.uid, resolved);
  const handle = await open(
    resolved,
    constants.O_RDONLY | directoryOnly | noFollow
  );
  try {
    const opened = await handle.stat();
    if (!sameIdentity(named, opened)) {
      throw localStatePathError(
        'Local state directory changed while it was being validated.'
      );
    }
    assertCurrentOwner(opened.uid, resolved);
    await handle.chmod(0o700);
    return identity(opened);
  } finally {
    await handle.close();
  }
}

/** Opens a regular local-state file without following a symlink and repairs mode through its handle. */
export async function openPrivateFile(filePath: string): Promise<string> {
  const resolved = path.resolve(filePath);
  const namedBefore = await lstat(resolved);
  if (namedBefore.isSymbolicLink() || !namedBefore.isFile()) {
    throw localStatePathError(
      'Local state file must be a regular, non-symlink file.'
    );
  }
  if (process.platform !== 'win32')
    assertCurrentOwner(namedBefore.uid, resolved);

  const handle = await open(resolved, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    const namedAfter = await lstat(resolved);
    if (
      namedAfter.isSymbolicLink() ||
      !namedAfter.isFile() ||
      !sameIdentity(namedBefore, opened) ||
      !sameIdentity(opened, namedAfter)
    ) {
      throw localStatePathError(
        'Local state file changed while it was being opened.'
      );
    }
    if (process.platform !== 'win32') {
      assertCurrentOwner(opened.uid, resolved);
      await handle.chmod(0o600);
    }
    return await handle.readFile('utf8');
  } finally {
    await handle.close();
  }
}

/** Rejects a symlink, non-file, or foreign-owned file before atomic replacement or removal. */
export async function validateRegularFileIfPresent(
  filePath: string
): Promise<void> {
  try {
    const value = await lstat(filePath);
    if (value.isSymbolicLink() || !value.isFile()) {
      throw localStatePathError(
        'Local state target must be a regular, non-symlink file.'
      );
    }
    if (process.platform !== 'win32') assertCurrentOwner(value.uid, filePath);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return;
    throw error;
  }
}

/** Verifies that the private parent directory still refers to its validated inode. */
export async function assertDirectoryIdentity(
  directoryPath: string,
  expected: DirectoryIdentity
): Promise<void> {
  const value = await lstat(directoryPath);
  if (
    value.isSymbolicLink() ||
    !value.isDirectory() ||
    value.dev !== expected.dev ||
    value.ino !== expected.ino
  ) {
    throw localStatePathError(
      'Local state directory changed during the operation.'
    );
  }
}

/** Persists directory entries where directory fsync is supported by the platform. */
export async function syncDirectory(directoryPath: string): Promise<void> {
  if (process.platform === 'win32') return;
  const handle = await open(
    directoryPath,
    constants.O_RDONLY | directoryOnly | noFollow
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function assertCurrentOwner(uid: number, filePath: string): void {
  if (typeof process.geteuid === 'function' && uid !== process.geteuid()) {
    throw localStatePathError(
      `Local state path is not owned by the current user: ${filePath}`
    );
  }
}

function sameIdentity(
  left: { dev: number; ino: number },
  right: { dev: number; ino: number }
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function identity(value: { dev: number; ino: number }): DirectoryIdentity {
  return { dev: value.dev, ino: value.ino };
}

function samePath(left: string, right: string): boolean {
  const a = path.normalize(left);
  const b = path.normalize(right);
  return process.platform === 'win32'
    ? a.toLocaleLowerCase('en-US') === b.toLocaleLowerCase('en-US')
    : a === b;
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function localStatePathError(message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code: 'UNSAFE_LOCAL_STATE_PATH' });
}
