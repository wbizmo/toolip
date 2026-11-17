import { constants } from 'node:fs';
import { lstat, open, readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import {
  assertDirectoryIdentity,
  ensurePrivateDirectory,
  syncDirectory,
  validateRegularFileIfPresent
} from '../../core/local-state-fs.js';
import { withLocalStateLock } from '../../core/local-lock.js';
import type { DeliveryLedger } from './delivery.js';

const keyPattern = /^[a-f0-9]{64}$/u;
const maximumEntries = 10_000;

/**
 * Durable at-most-once claims across same-host workers. The directory must
 * be chosen by the operator, outside a scanned repository. Successful claims
 * are retained without automatic expiry: deleting them can permit duplicates.
 *
 * A crash after claim but before HTTP delivery can leave an undelivered
 * claim. This is intentionally at-most-once, not guaranteed delivery.
 */
export class FileDeliveryLedger implements DeliveryLedger {
  private readonly resource: string;

  constructor(
    private readonly directory: string,
    private readonly limit = maximumEntries
  ) {
    if (!path.isAbsolute(directory) ||
        directory === path.parse(directory).root)
      throw new TypeError('Delivery ledger requires an absolute private state directory.');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > maximumEntries)
      throw new RangeError('Delivery ledger capacity must be between 1 and 10000.');
    this.resource = path.join(directory, '.delivery-ledger');
  }

  private location(key: string): string {
    if (!keyPattern.test(key))
      throw new TypeError('Delivery ledger key must be a fixed SHA-256 hex digest.');
    return path.join(this.directory, key);
  }

  async claim(key: string): Promise<boolean> {
    const file = this.location(key);
    const identity = await ensurePrivateDirectory(this.directory);
    return withLocalStateLock(this.resource, async (assertOwned) => {
      await assertOwned();
      await assertDirectoryIdentity(this.directory, identity);
      let present = false;
      try {
        const existing = await lstat(file);
        if (!existing.isFile() || existing.isSymbolicLink())
          throw new Error('Delivery ledger claim path is unsafe.');
        present = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
          throw error;
      }
      if (present) return false;

      const entries = await readdir(this.directory, { withFileTypes: true });
      let count = 0;
      for (const entry of entries) {
        if (keyPattern.test(entry.name)) {
          if (!entry.isFile() || entry.isSymbolicLink())
            throw new Error('Delivery ledger contains an unsafe claim entry.');
          if (++count >= this.limit)
            throw new Error('Delivery ledger has reached its retention capacity.');
        }
      }
      await assertOwned();
      const handle = await open(
        file,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
          (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW),
        0o600
      );
      try {
        await handle.writeFile('claimed\n');
        await handle.sync();
      } finally {
        await handle.close();
      }
      await assertDirectoryIdentity(this.directory, identity);
      await syncDirectory(this.directory);
      return true;
    });
  }

  async release(key: string): Promise<void> {
    const file = this.location(key);
    const identity = await ensurePrivateDirectory(this.directory);
    await withLocalStateLock(this.resource, async (assertOwned) => {
      await assertOwned();
      await assertDirectoryIdentity(this.directory, identity);
      await validateRegularFileIfPresent(file);
      try {
        await unlink(file);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      await syncDirectory(this.directory);
    });
  }
}
