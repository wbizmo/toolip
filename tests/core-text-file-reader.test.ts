import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { TextFileReader } from '../src/core/text-file-reader.js';

const roots: string[] = [];

async function tempFile(name: string, content: string | Buffer): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-reader-'));
  roots.push(root);
  const file = path.join(root, name);
  await writeFile(file, content);
  return file;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

describe('TextFileReader', () => {
  it('rejects oversized files before loading them', async () => {
    const file = await tempFile('large.txt', '12345');
    const reader = new TextFileReader({
      maxFiles: 10,
      maxFileBytes: 4,
      maxTotalBytes: 100
    });

    await expect(reader.read(file)).resolves.toMatchObject({
      status: 'oversized',
      bytes: 5
    });
  });

  it('skips binary files', async () => {
    const file = await tempFile('binary.dat', Buffer.from([65, 0, 66]));
    const reader = new TextFileReader({
      maxFiles: 10,
      maxFileBytes: 100,
      maxTotalBytes: 100
    });

    await expect(reader.read(file)).resolves.toMatchObject({
      status: 'binary'
    });
  });

  it('enforces total byte and file-count budgets', async () => {
    const first = await tempFile('first.txt', '1234');
    const second = await tempFile('second.txt', '5678');
    const totalReader = new TextFileReader({
      maxFiles: 10,
      maxFileBytes: 100,
      maxTotalBytes: 6
    });

    await expect(totalReader.read(first)).resolves.toMatchObject({ status: 'ok' });
    await expect(totalReader.read(second)).resolves.toMatchObject({
      status: 'budget-exceeded'
    });

    const fileCountReader = new TextFileReader({
      maxFiles: 1,
      maxFileBytes: 100,
      maxTotalBytes: 100
    });

    await expect(fileCountReader.read(first)).resolves.toMatchObject({ status: 'ok' });
    await expect(fileCountReader.read(second)).resolves.toMatchObject({
      status: 'budget-exceeded'
    });
  });
});
