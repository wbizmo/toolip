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
  const named = await lstat(absolute, { bigint: true });
  if (named.isSymbolicLink() || !named.isFile())
    throw new Error('PEM key path must be a regular, non-symlink file.');
  if (named.size === 0n || named.size > BigInt(maxPemBytes))
    throw new Error('PEM key file is empty or exceeds the size limit.');
  if (
    options.privateKey &&
    process.platform !== 'win32' &&
    (Number(named.mode) & 0o077) !== 0
  )
    throw new Error('Private PEM key permissions must be owner-only.');
  const handle = await open(
    absolute,
    constants.O_RDONLY |
      noFollow |
      (process.platform === 'win32' ? 0 : constants.O_NONBLOCK)
  );
  try {
    const opened = await handle.stat({ bigint: true });
    const after = await lstat(absolute, { bigint: true });
    if (
      !opened.isFile() ||
      after.isSymbolicLink() ||
      !after.isFile() ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.dev !== named.dev ||
      opened.ino !== named.ino ||
      opened.size !== named.size ||
      opened.size === 0n ||
      opened.size > BigInt(maxPemBytes) ||
      (options.privateKey &&
        process.platform !== 'win32' &&
        (Number(opened.mode) & 0o077) !== 0)
    )
      throw new Error('PEM key file changed while it was being opened.');

    const bytes = Buffer.alloc(maxPemBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        length,
        bytes.length - length,
        null
      );
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    const finalHandle = await handle.stat({ bigint: true });
    const finalPath = await lstat(absolute, { bigint: true });
    if (
      length === 0 ||
      length > maxPemBytes ||
      BigInt(length) !== opened.size ||
      finalHandle.dev !== opened.dev ||
      finalHandle.ino !== opened.ino ||
      finalHandle.size !== opened.size ||
      (options.privateKey &&
        process.platform !== 'win32' &&
        (Number(finalHandle.mode) & 0o077) !== 0) ||
      finalHandle.mtimeNs !== opened.mtimeNs ||
      finalHandle.ctimeNs !== opened.ctimeNs ||
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino
    )
      throw new Error('PEM key file is empty or exceeds the size limit.');
    return new TextDecoder('utf-8', { fatal: true }).decode(
      bytes.subarray(0, length)
    );
  } finally {
    await handle.close();
  }
}
