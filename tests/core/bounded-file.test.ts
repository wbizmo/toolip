import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  readBoundedRegularFile,
  readBoundedUtf8File
} from '../../src/core/bounded-file.js';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function fixture(): { root: string; file: string } {
  const root = mkdtempSync(path.join(os.tmpdir(), 'toolip-bounded-file-'));
  roots.push(root);
  return { root, file: path.join(root, 'input.txt') };
}

describe('bounded file reads', () => {
  it('reads an unchanged regular file within the byte ceiling', async () => {
    const { file } = fixture();
    writeFileSync(file, 'safe input');

    await expect(readBoundedUtf8File(file, 10)).resolves.toBe('safe input');
    await expect(readBoundedRegularFile(file, 10)).resolves.toEqual(
      Buffer.from('safe input')
    );
  });

  it('rejects an input larger than the ceiling', async () => {
    const { file } = fixture();
    writeFileSync(file, 'larger than the cap');

    await expect(readBoundedRegularFile(file, 4)).rejects.toThrow(/bounded/);
  });

  it.skipIf(process.platform === 'win32')(
    'rejects symbolic links even when their target is a bounded file',
    async () => {
      const { file } = fixture();
      const link = path.join(path.dirname(file), 'linked.txt');
      writeFileSync(file, 'safe input');
      symlinkSync(file, link);

      await expect(readBoundedRegularFile(link, 10)).rejects.toThrow(
        /bounded regular non-symlink/
      );
    }
  );

  it('rejects invalid UTF-8 instead of silently replacing bytes', async () => {
    const { file } = fixture();
    writeFileSync(file, Buffer.from([0xff]));

    await expect(readBoundedUtf8File(file, 1)).rejects.toThrow();
  });
});
