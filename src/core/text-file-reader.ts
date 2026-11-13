import { createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { type FileHandle, open } from 'node:fs/promises';
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';

export type TextFileBudget = {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
};

export type FileSnapshot = {
  dev: bigint;
  ino: bigint;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  mtimeNs: bigint;
  ctimeNs: bigint;
};

export type TextFileReadResult =
  | {
      status: 'ok';
      content: string;
      bytes: number;
      sha256?: string;
      snapshot?: FileSnapshot;
    }
  | {
      status: 'oversized' | 'budget-exceeded' | 'cancelled' | 'changed';
      bytes: number;
    }
  | {
      status: 'binary';
      bytes: number;
      sha256?: string;
      snapshot?: FileSnapshot;
    }
  | { status: 'failed'; bytes: 0; error: string };

export const defaultTextFileBudget: TextFileBudget = {
  maxFiles: 20_000,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024
};

export const MAX_TEXT_FILE_READ_CONCURRENCY = 32;
const defaultTextFileReadConcurrency = 8;

type ReadSlotWaiter = {
  signal?: AbortSignal;
  resolve: (acquired: boolean) => void;
  abort?: () => void;
};

export type TextFileReaderOptions = {
  root?: string;
  maxConcurrentReads?: number;
  openFile?: (filePath: string, flags: number) => Promise<FileHandle>;
  realpathFile?: (filePath: string) => Promise<string>;
  lstatFile?: (
    filePath: string,
    options: { bigint: true }
  ) => Promise<BigIntStats>;
};

/** Compares all discovery/read identity fields for a file snapshot. */
function sameSnapshot(a: FileSnapshot, b: FileSnapshot): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.size === b.size &&
    a.mtimeMs === b.mtimeMs &&
    a.ctimeMs === b.ctimeMs &&
    a.mtimeNs === b.mtimeNs &&
    a.ctimeNs === b.ctimeNs
  );
}

/** Converts bigint filesystem metadata to bounded numeric content metadata. */
export function snapshotOf(stat: BigIntStats): FileSnapshot {
  return {
    dev: stat.dev,
    ino: stat.ino,
    size: Number(stat.size),
    mtimeMs: Number(stat.mtimeMs),
    ctimeMs: Number(stat.ctimeMs),
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs
  };
}

/** Tests canonical path containment without relying on string prefixes. */
function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

/** Reads bounded text snapshots and rejects incomplete or changed inputs. */
export class TextFileReader {
  private filesRead = 0;
  private filesInFlight = 0;
  private activeReads = 0;
  private peakConcurrentReads = 0;
  private readonly queuedReads: ReadSlotWaiter[] = [];
  private bytesRead = 0;
  private readonly budget: TextFileBudget;
  private readonly maxConcurrentReads: number;
  private readonly root?: string;
  private readonly openFile: NonNullable<TextFileReaderOptions['openFile']>;
  private readonly realpathFile: NonNullable<
    TextFileReaderOptions['realpathFile']
  >;
  private readonly lstatFile: NonNullable<TextFileReaderOptions['lstatFile']>;

  /** Validates and stores the read budgets and filesystem dependencies. */
  constructor(
    budget: TextFileBudget = defaultTextFileBudget,
    options: TextFileReaderOptions = {}
  ) {
    for (const value of Object.values(budget)) {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError(
          'Text file budgets must be non-negative safe integers.'
        );
      }
    }
    this.budget = { ...budget };
    this.maxConcurrentReads =
      options.maxConcurrentReads ?? defaultTextFileReadConcurrency;
    if (
      !Number.isSafeInteger(this.maxConcurrentReads) ||
      this.maxConcurrentReads < 1 ||
      this.maxConcurrentReads > MAX_TEXT_FILE_READ_CONCURRENCY
    )
      throw new RangeError(
        `Text file read concurrency must be between 1 and ${MAX_TEXT_FILE_READ_CONCURRENCY}.`
      );
    this.root =
      options.root === undefined ? undefined : path.resolve(options.root);
    this.openFile = options.openFile ?? open;
    this.realpathFile = options.realpathFile ?? realpath;
    this.lstatFile = options.lstatFile ?? lstat;
  }

  /** Returns completed file and byte totals for this reader instance. */
  get usage(): { filesRead: number; bytesRead: number } {
    return { filesRead: this.filesRead, bytesRead: this.bytesRead };
  }

  get activeReadCount(): number {
    return this.activeReads;
  }

  get queuedReadCount(): number {
    return this.queuedReads.length;
  }

  get peakConcurrentReadCount(): number {
    return this.peakConcurrentReads;
  }

  private acquireReadSlot(signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return Promise.resolve(false);
    if (this.activeReads < this.maxConcurrentReads) {
      this.activeReads += 1;
      this.peakConcurrentReads = Math.max(
        this.peakConcurrentReads,
        this.activeReads
      );
      return Promise.resolve(true);
    }
    return new Promise<boolean>((resolve) => {
      const waiter: ReadSlotWaiter = { signal, resolve };
      waiter.abort = () => {
        const index = this.queuedReads.indexOf(waiter);
        if (index < 0) return;
        this.queuedReads.splice(index, 1);
        signal?.removeEventListener('abort', waiter.abort as () => void);
        resolve(false);
      };
      this.queuedReads.push(waiter);
      signal?.addEventListener('abort', waiter.abort, { once: true });
      if (signal?.aborted) waiter.abort();
    });
  }

  private releaseReadSlot(): void {
    while (this.queuedReads.length > 0) {
      const waiter = this.queuedReads.shift();
      if (!waiter) continue;
      waiter.signal?.removeEventListener('abort', waiter.abort as () => void);
      if (waiter.signal?.aborted) {
        waiter.resolve(false);
        continue;
      }
      // Transfer the existing permit directly to the next queued reader.
      waiter.resolve(true);
      return;
    }
    this.activeReads = Math.max(0, this.activeReads - 1);
  }

  /** Reads exactly one bounded file snapshot, honoring cancellation and root. */
  async read(
    filePath: string,
    signal?: AbortSignal,
    expected?: FileSnapshot
  ): Promise<TextFileReadResult> {
    if (signal?.aborted) return { status: 'cancelled', bytes: 0 };
    if (this.filesRead + this.filesInFlight >= this.budget.maxFiles) {
      return { status: 'budget-exceeded', bytes: 0 };
    }

    this.filesInFlight += 1;
    let handle: FileHandle | undefined;
    let reservedBytes = 0;
    let hasReadSlot = false;
    try {
      hasReadSlot = await this.acquireReadSlot(signal);
      if (!hasReadSlot) return { status: 'cancelled', bytes: 0 };
      if (signal?.aborted) return { status: 'cancelled', bytes: 0 };
      const absolutePath = path.resolve(filePath);
      const trustedRoot =
        this.root === undefined
          ? undefined
          : await this.realpathFile(this.root);
      if (signal?.aborted) return { status: 'cancelled', bytes: 0 };
      if (trustedRoot !== undefined) {
        const before = await this.realpathFile(absolutePath);
        if (signal?.aborted) return { status: 'cancelled', bytes: 0 };
        if (!isWithin(trustedRoot, before))
          return { status: 'changed', bytes: 0 };
      }

      const noFollow = constants.O_NOFOLLOW ?? 0;
      const nonBlocking =
        process.platform === 'win32' ? 0 : (constants.O_NONBLOCK ?? 0);
      handle = await this.openFile(
        absolutePath,
        constants.O_RDONLY | noFollow | nonBlocking
      );
      if (signal?.aborted) return { status: 'cancelled', bytes: 0 };
      const beforeStat = await handle.stat({ bigint: true });
      if (signal?.aborted) return { status: 'cancelled', bytes: 0 };
      if (!beforeStat.isFile()) return { status: 'changed', bytes: 0 };
      const before = snapshotOf(beforeStat);
      if (expected && !sameSnapshot(expected, before)) {
        return { status: 'changed', bytes: before.size };
      }
      if (
        beforeStat.size > BigInt(Number.MAX_SAFE_INTEGER) ||
        !Number.isSafeInteger(before.size) ||
        before.size < 0
      ) {
        return { status: 'changed', bytes: 0 };
      }
      if (before.size > this.budget.maxFileBytes) {
        return { status: 'oversized', bytes: before.size };
      }
      if (this.bytesRead + before.size > this.budget.maxTotalBytes) {
        return { status: 'budget-exceeded', bytes: before.size };
      }
      reservedBytes = before.size;
      this.bytesRead += reservedBytes;

      const buffer = Buffer.alloc(before.size);
      let offset = 0;
      while (offset < before.size) {
        if (signal?.aborted) return { status: 'cancelled', bytes: offset };
        const { bytesRead } = await handle.read(
          buffer,
          offset,
          before.size - offset,
          offset
        );
        if (bytesRead === 0) return { status: 'changed', bytes: offset };
        offset += bytesRead;
        if (signal?.aborted) return { status: 'cancelled', bytes: offset };
      }
      if (signal?.aborted) return { status: 'cancelled', bytes: offset };

      const extra = Buffer.alloc(1);
      const grown = await handle.read(extra, 0, 1, before.size);
      if (signal?.aborted) return { status: 'cancelled', bytes: offset };
      const afterStat = await handle.stat({ bigint: true });
      if (signal?.aborted) return { status: 'cancelled', bytes: offset };
      const after = snapshotOf(afterStat);
      if (grown.bytesRead !== 0 || !sameSnapshot(before, after)) {
        return { status: 'changed', bytes: offset + grown.bytesRead };
      }

      const pathStat = await this.lstatFile(absolutePath, { bigint: true });
      if (signal?.aborted) return { status: 'cancelled', bytes: offset };
      if (
        pathStat.isSymbolicLink() ||
        !sameSnapshot(before, snapshotOf(pathStat))
      ) {
        return { status: 'changed', bytes: offset };
      }
      if (trustedRoot !== undefined) {
        const afterPath = await this.realpathFile(absolutePath);
        if (signal?.aborted) return { status: 'cancelled', bytes: offset };
        if (!isWithin(trustedRoot, afterPath))
          return { status: 'changed', bytes: offset };
      }
      if (buffer.subarray(0, Math.min(buffer.length, 8 * 1024)).includes(0)) {
        this.filesRead += 1;
        reservedBytes = 0;
        return {
          status: 'binary',
          bytes: offset,
          sha256: createHash('sha256').update(buffer).digest('hex'),
          snapshot: before
        };
      }

      this.filesRead += 1;
      reservedBytes = 0;
      return {
        status: 'ok',
        content: buffer.toString('utf8'),
        bytes: offset,
        sha256: createHash('sha256').update(buffer).digest('hex'),
        snapshot: before
      };
    } catch (error) {
      if (
        error !== null &&
        typeof error === 'object' &&
        'code' in error &&
        error.code === 'ELOOP'
      ) {
        return { status: 'changed', bytes: 0 };
      }
      return {
        status: 'failed',
        bytes: 0,
        error: error instanceof Error ? error.message : String(error)
      };
    } finally {
      this.filesInFlight -= 1;
      if (reservedBytes > 0) this.bytesRead -= reservedBytes;
      // Keep the I/O permit until the OS handle is actually closed, including
      // slow and rejected close operations. A queued read must never overlap it.
      try {
        await handle?.close();
      } finally {
        if (hasReadSlot) this.releaseReadSlot();
      }
    }
  }
}
