import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FileDeliveryLedger } from '../../src/integrations/notifications/file-ledger.js';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function privateDirectory() {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'toolip-delivery-ledger-'));
  roots.push(parent);
  return path.join(parent, 'notifications');
}
const key = 'a'.repeat(64);

describe('durable notification delivery ledger', () => {
  it('persists duplicate suppression across independent workers', async () => {
    const directory = await privateDirectory();
    const first = new FileDeliveryLedger(directory);
    const second = new FileDeliveryLedger(directory);
    expect(await first.claim(key)).toBe(true);
    expect(await second.claim(key)).toBe(false);
    expect(await new FileDeliveryLedger(directory).claim(key)).toBe(false);
  });

  it('allows retry only after the failed delivery releases its claim', async () => {
    const directory = await privateDirectory();
    const first = new FileDeliveryLedger(directory);
    expect(await first.claim(key)).toBe(true);
    await first.release(key);
    expect(await new FileDeliveryLedger(directory).claim(key)).toBe(true);
  });

  it('never silently evicts a prior successful claim when capacity is full', async () => {
    const directory = await privateDirectory();
    const ledger = new FileDeliveryLedger(directory, 1);
    expect(await ledger.claim(key)).toBe(true);
    await expect(ledger.claim('b'.repeat(64))).rejects.toThrow(
      'retention capacity'
    );
    expect(await ledger.claim(key)).toBe(false);
  });

  it('rejects arbitrary paths and invalid claim tokens', async () => {
    const directory = await privateDirectory();
    const ledger = new FileDeliveryLedger(directory);
    await expect(ledger.claim('../other')).rejects.toThrow('SHA-256');
    expect(() => new FileDeliveryLedger('relative/path')).toThrow('absolute');
  });
});
