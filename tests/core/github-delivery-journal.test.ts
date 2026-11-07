import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GitHubAppDeliveryJournal } from '../../src/core/github/delivery-journal.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function journalFixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-github-journal-'));
  roots.push(root);
  const file = path.join(root, 'state', 'deliveries.json');
  return { file, journal: new GitHubAppDeliveryJournal(file) };
}

describe('durable GitHub App delivery journal', () => {
  it('persists delivery claims across instances and permits replay only after expiry', async () => {
    const { file, journal } = await journalFixture();
    const options = { now: 1_000, ttlMs: 100, limit: 10 };
    await expect(journal.claim('delivery-1', options)).resolves.toBe(true);
    await expect(
      new GitHubAppDeliveryJournal(file).claim('delivery-1', options)
    ).resolves.toBe(false);
    await expect(
      new GitHubAppDeliveryJournal(file).claim('delivery-1', {
        ...options,
        now: 1_100
      })
    ).resolves.toBe(true);
  });

  it('serializes competing processes and fails closed when the retention budget is full', async () => {
    const { file, journal } = await journalFixture();
    const peer = new GitHubAppDeliveryJournal(file);
    const outcomes = await Promise.all([
      journal.claim('same-delivery', { now: 5_000, ttlMs: 1_000, limit: 1 }),
      peer.claim('same-delivery', { now: 5_000, ttlMs: 1_000, limit: 1 })
    ]);
    expect(outcomes.sort()).toEqual([false, true]);
    await expect(
      journal.claim('next-delivery', { now: 5_000, ttlMs: 1_000, limit: 1 })
    ).rejects.toThrow('journal is full');
  });

  it('persists installation suspension and clears it only on a new valid transition', async () => {
    const { file, journal } = await journalFixture();
    const claim = (deliveryId: string, suspended: boolean) =>
      journal.claim(deliveryId, {
        now: 8_000,
        ttlMs: 10_000,
        limit: 10,
        installation: { id: 42, suspended }
      });
    await expect(claim('suspend-1', true)).resolves.toBe(true);
    await expect(
      new GitHubAppDeliveryJournal(file).snapshot()
    ).resolves.toEqual({ suspendedInstallations: [42] });
    await expect(claim('suspend-1', false)).resolves.toBe(false);
    await expect(claim('unsuspend-2', false)).resolves.toBe(true);
    await expect(
      new GitHubAppDeliveryJournal(file).snapshot()
    ).resolves.toEqual({ suspendedInstallations: [] });
  });
});
