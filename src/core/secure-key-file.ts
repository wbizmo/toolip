import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';

const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
const maxPemBytes = 16 * 1024;

/** Read a bounded PEM key without following links or exposing private key bytes. */
export async function readPemKeyFile(
  filePath: string,
  options: { privateKey?: boolean } = {}
): Promise<string> {
  const absolute = path.resolve(filePath);
  const named = await lstat(absolute);
  if (named.isSymbolicLink() || !named.isFile())
    throw new Error('PEM key path must be a regular, non-symlink file.');
  if (named.size === 0 || named.size > maxPemBytes)
    throw new Error('PEM key file is empty or exceeds the size limit.');
  if (
    options.privateKey &&
    process.platform !== 'win32' &&
    (named.mode & 0o077) !== 0
  )
    throw new Error('Private PEM key permissions must be owner-only.');
  const handle = await open(
    absolute,
    constants.O_RDONLY |
      noFollow |
      (process.platform === 'win32' ? 0 : constants.O_NONBLOCK)
  );
  try {
    const opened = await handle.stat();
    const after = await lstat(absolute);
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino
    )
      throw new Error('PEM key file changed while it was being opened.');
    const bytes = await handle.readFile();
    if (bytes.length === 0 || bytes.length > maxPemBytes)
      throw new Error('PEM key file is empty or exceeds the size limit.');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } finally {
    await handle.close();
  }
}
