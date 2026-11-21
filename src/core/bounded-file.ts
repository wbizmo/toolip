import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';

/** Read an unchanged regular file with a strict byte ceiling. */
export async function readBoundedRegularFile(
  filePath: string,
  maximumBytes: number
): Promise<Buffer> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0)
    throw new RangeError('maximumBytes must be a non-negative safe integer.');
  const before = await lstat(filePath, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile())
    throw new Error('Input must be a bounded regular non-symlink file.');
  if (before.size > BigInt(maximumBytes))
    throw Object.assign(new Error('Input exceeds its bounded byte limit.'), {
      code: 'ERR_FILE_TOO_LARGE'
    });
  const handle = await open(
    filePath,
    constants.O_RDONLY |
      (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
  );
  try {
    const opened = await handle.stat({ bigint: true });
    const afterOpen = await lstat(filePath, { bigint: true });
    if (
      !opened.isFile() ||
      afterOpen.isSymbolicLink() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.dev !== afterOpen.dev ||
      opened.ino !== afterOpen.ino ||
      opened.mtimeNs !== before.mtimeNs ||
      opened.ctimeNs !== before.ctimeNs ||
      opened.size !== before.size ||
      opened.size > BigInt(maximumBytes)
    )
      throw new Error('Input changed while it was being opened.');

    const bytes = Buffer.alloc(Number(opened.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        length,
        Math.min(64 * 1024, bytes.length - length),
        null
      );
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    const finished = await handle.stat({ bigint: true });
    const afterRead = await lstat(filePath, { bigint: true });
    if (length > maximumBytes)
      throw Object.assign(new Error('Input exceeds its bounded byte limit.'), {
        code: 'ERR_FILE_TOO_LARGE'
      });
    if (
      BigInt(length) !== opened.size ||
      finished.dev !== opened.dev ||
      finished.ino !== opened.ino ||
      finished.size !== opened.size ||
      finished.mtimeNs !== opened.mtimeNs ||
      finished.ctimeNs !== opened.ctimeNs ||
      afterRead.isSymbolicLink() ||
      afterRead.dev !== opened.dev ||
      afterRead.ino !== opened.ino ||
      afterRead.size !== opened.size ||
      afterRead.mtimeNs !== opened.mtimeNs ||
      afterRead.ctimeNs !== opened.ctimeNs
    )
      throw new Error('Input changed while it was being read.');
    return bytes.subarray(0, length);
  } finally {
    await handle.close();
  }
}

export async function readBoundedUtf8File(
  filePath: string,
  maximumBytes: number
): Promise<string> {
  return new TextDecoder('utf-8', { fatal: true }).decode(
    await readBoundedRegularFile(filePath, maximumBytes)
  );
}
