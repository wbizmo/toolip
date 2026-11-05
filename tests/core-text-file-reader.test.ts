import {
  open as openFile,
  mkdtemp,
  rm,
  symlink,
  truncate,
  utimes,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { walkProjectFiles } from '../src/core/file-walker.js';
import {
  TextFileReader,
  type FileSnapshot
} from '../src/core/text-file-reader.js';

const roots: string[] = [];

async function tempFile(
  name: string,
  content: string | Buffer
): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-reader-'));
  roots.push(root);
  const file = path.join(root, name);
  await writeFile(file, content);
  return file;
}

async function snapshot(file: string): Promise<FileSnapshot> {
  const { stat } = await import('node:fs/promises');
  const value = await stat(file, { bigint: true });
  return {
    dev: value.dev,
    ino: value.ino,
    size: Number(value.size),
    mtimeMs: Number(value.mtimeMs),
    ctimeMs: Number(value.ctimeMs)
  };
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

    await expect(totalReader.read(first)).resolves.toMatchObject({
      status: 'ok'
    });
    await expect(totalReader.read(second)).resolves.toMatchObject({
      status: 'budget-exceeded'
    });

    const fileCountReader = new TextFileReader({
      maxFiles: 1,
      maxFileBytes: 100,
      maxTotalBytes: 100
    });

    await expect(fileCountReader.read(first)).resolves.toMatchObject({
      status: 'ok'
    });
    await expect(fileCountReader.read(second)).resolves.toMatchObject({
      status: 'budget-exceeded'
    });
  });

  it('reserves file-count budget across concurrent reads', async () => {
    const first = await tempFile('parallel-a.txt', 'a');
    const second = await tempFile('parallel-b.txt', 'b');
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const reader = new TextFileReader(
      { maxFiles: 1, maxFileBytes: 10, maxTotalBytes: 10 },
      {
        openFile: async (filePath, flags) => {
          await gate;
          return openFile(filePath, flags);
        }
      }
    );
    const firstRead = reader.read(first);
    await expect(reader.read(second)).resolves.toMatchObject({
      status: 'budget-exceeded'
    });
    release();
    await expect(firstRead).resolves.toMatchObject({
      status: 'ok',
      content: 'a'
    });
  });

  it('reads exact size boundaries using initialized output and hashes the snapshot', async () => {
    const file = await tempFile('boundary.txt', '1234');
    const reader = new TextFileReader(
      { maxFiles: 1, maxFileBytes: 4, maxTotalBytes: 4 },
      { root: path.dirname(file) }
    );
    await expect(
      reader.read(file, undefined, await snapshot(file))
    ).resolves.toEqual({
      status: 'ok',
      content: '1234',
      bytes: 4,
      sha256: createHash('sha256').update('1234').digest('hex')
    });
    expect(reader.usage).toEqual({ filesRead: 1, bytesRead: 4 });
  });

  it('loops over short reads rather than accepting a partial buffer', async () => {
    const file = await tempFile('short.txt', 'abcdef');
    const reader = new TextFileReader(undefined, {
      openFile: async (filePath, flags) => {
        const handle = await openFile(filePath, flags);
        return new Proxy(handle, {
          get(target, property) {
            if (property === 'read') {
              return (
                buffer: Buffer,
                offset: number,
                length: number,
                position: number
              ) => target.read(buffer, offset, Math.min(length, 2), position);
            }
            const value = Reflect.get(target, property, target) as unknown;
            return typeof value === 'function' ? value.bind(target) : value;
          }
        });
      }
    });
    await expect(reader.read(file)).resolves.toMatchObject({
      status: 'ok',
      content: 'abcdef',
      bytes: 6
    });
  });

  it('marks shrink, growth, and discovery identity changes incomplete', async () => {
    const shrunk = await tempFile('shrunk.txt', 'abcdef');
    let shrunkOnce = false;
    const shortReader = new TextFileReader(undefined, {
      openFile: async (filePath, flags) => {
        const handle = await openFile(filePath, flags);
        return new Proxy(handle, {
          get(target, property) {
            if (property === 'read') {
              return async (
                buffer: Buffer,
                offset: number,
                length: number,
                position: number
              ) => {
                const result = await target.read(
                  buffer,
                  offset,
                  Math.min(length, 2),
                  position
                );
                if (!shrunkOnce) {
                  shrunkOnce = true;
                  await truncate(filePath, 0);
                }
                return result;
              };
            }
            const value = Reflect.get(target, property, target) as unknown;
            return typeof value === 'function' ? value.bind(target) : value;
          }
        });
      }
    });
    await expect(shortReader.read(shrunk)).resolves.toMatchObject({
      status: 'changed'
    });
    expect(shortReader.usage).toEqual({ filesRead: 0, bytesRead: 0 });

    const grown = await tempFile('grown.txt', 'abcd');
    let grownOnce = false;
    const growthReader = new TextFileReader(undefined, {
      openFile: async (filePath, flags) => {
        const handle = await openFile(filePath, flags);
        return new Proxy(handle, {
          get(target, property) {
            if (property === 'read') {
              return async (
                buffer: Buffer,
                offset: number,
                length: number,
                position: number
              ) => {
                const result = await target.read(
                  buffer,
                  offset,
                  length,
                  position
                );
                if (!grownOnce) {
                  grownOnce = true;
                  await writeFile(filePath, 'abcdef');
                }
                return result;
              };
            }
            const value = Reflect.get(target, property, target) as unknown;
            return typeof value === 'function' ? value.bind(target) : value;
          }
        });
      }
    });
    await expect(growthReader.read(grown)).resolves.toMatchObject({
      status: 'changed'
    });

    const replaced = await tempFile('replaced.txt', 'before');
    const before = await snapshot(replaced);
    await writeFile(replaced, 'after!');
    const later = new Date(before.mtimeMs + 1_000);
    await utimes(replaced, later, later);
    await expect(
      new TextFileReader().read(replaced, undefined, before)
    ).resolves.toMatchObject({ status: 'changed' });
  });

  it('stops after cancellation during a partial read without counting the file', async () => {
    const file = await tempFile('cancelled.txt', 'abcdef');
    const controller = new AbortController();
    const reader = new TextFileReader(undefined, {
      openFile: async (filePath, flags) => {
        const handle = await openFile(filePath, flags);
        return new Proxy(handle, {
          get(target, property) {
            if (property === 'read') {
              return async (
                buffer: Buffer,
                offset: number,
                length: number,
                position: number
              ) => {
                const result = await target.read(
                  buffer,
                  offset,
                  Math.min(length, 2),
                  position
                );
                if (position === 0) controller.abort();
                return result;
              };
            }
            const value = Reflect.get(target, property, target) as unknown;
            return typeof value === 'function' ? value.bind(target) : value;
          }
        });
      }
    });
    await expect(reader.read(file, controller.signal)).resolves.toMatchObject({
      status: 'cancelled'
    });
    expect(reader.usage).toEqual({ filesRead: 0, bytesRead: 0 });
  });

  it.skipIf(process.platform === 'win32')(
    'rejects symlinks escaping the walked workspace',
    async () => {
      const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-root-'));
      roots.push(root);
      const outside = await tempFile('outside.txt', 'secret');
      const link = path.join(root, 'linked.txt');
      await symlink(outside, link);
      const files = await walkProjectFiles(root);
      expect(files.map((file) => file.relativePath)).toContain('linked.txt');
      const reader = new TextFileReader(undefined, { root });
      const linked = files.find((file) => file.relativePath === 'linked.txt');
      expect(linked).toBeDefined();
      await expect(
        reader.read(link, undefined, linked?.snapshot)
      ).resolves.toMatchObject({ status: 'changed' });
    }
  );

  it.skipIf(process.platform === 'win32')(
    'fails discovery when a symbolic directory hides unscanned inputs',
    async () => {
      const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-root-'));
      roots.push(root);
      const outsideRoot = await mkdtemp(path.join(os.tmpdir(), 'toolip-dir-'));
      roots.push(outsideRoot);
      await writeFile(path.join(outsideRoot, 'hidden.ts'), 'const x = 1;');
      await symlink(outsideRoot, path.join(root, 'linked-dir'), 'dir');
      await expect(walkProjectFiles(root)).rejects.toMatchObject({
        code: 'SCAN_DISCOVERY_INCOMPLETE'
      });
    }
  );
});
