import { open } from 'node:fs/promises';

export type TextFileBudget = {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
};

export type TextFileReadResult =
  | { status: 'ok'; content: string; bytes: number }
  | { status: 'oversized' | 'binary' | 'budget-exceeded' | 'cancelled'; bytes: number }
  | { status: 'failed'; bytes: 0; error: string };

export const defaultTextFileBudget: TextFileBudget = {
  maxFiles: 20_000,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024
};

export class TextFileReader {
  private filesRead = 0;
  private bytesRead = 0;

  constructor(
    private readonly budget: TextFileBudget = defaultTextFileBudget
  ) {}

  get usage(): { filesRead: number; bytesRead: number } {
    return {
      filesRead: this.filesRead,
      bytesRead: this.bytesRead
    };
  }

  async read(
    filePath: string,
    signal?: AbortSignal
  ): Promise<TextFileReadResult> {
    if (signal?.aborted) {
      return { status: 'cancelled', bytes: 0 };
    }

    if (this.filesRead >= this.budget.maxFiles) {
      return { status: 'budget-exceeded', bytes: 0 };
    }

    let handle;

    try {
      handle = await open(filePath, 'r');
      const { size } = await handle.stat();

      if (size > this.budget.maxFileBytes) {
        return { status: 'oversized', bytes: size };
      }

      if (this.bytesRead + size > this.budget.maxTotalBytes) {
        return { status: 'budget-exceeded', bytes: size };
      }

      const sampleLength = Math.min(size, 8 * 1024);
      if (sampleLength > 0) {
        const sample = Buffer.allocUnsafe(sampleLength);
        await handle.read(sample, 0, sampleLength, 0);

        if (sample.includes(0)) {
          return { status: 'binary', bytes: size };
        }
      }

      if (signal?.aborted) {
        return { status: 'cancelled', bytes: 0 };
      }

      const buffer = Buffer.allocUnsafe(size);
      if (size > 0) {
        await handle.read(buffer, 0, size, 0);
      }

      this.filesRead += 1;
      this.bytesRead += size;

      return {
        status: 'ok',
        content: buffer.toString('utf8'),
        bytes: size
      };
    } catch (error) {
      return {
        status: 'failed',
        bytes: 0,
        error: error instanceof Error ? error.message : String(error)
      };
    } finally {
      await handle?.close();
    }
  }
}
