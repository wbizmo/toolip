import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import {
  evaluateStageA,
  runStageB
} from '../../src/core/pre-execution-gate.js';

describe('pre-execution Stage A trust gate', () => {
  it('requires an allowlisted scanner and complete known input result', async () => {
    const scannerBytes = Buffer.from('trusted-scanner-fixture');
    const policy = { scannerSha256Allowlist: ['not-the-digest'] };
    let ran = false;
    const { result, approval } = evaluateStageA({
      policy,
      scannerBytes,
      blobs: [],
      scannerAvailable: true,
      completed: true,
      findingsKnown: true,
      blocked: false
    });
    expect(result.status).toBe('blocked');
    await expect(
      runStageB(approval as never, async () => {
        ran = true;
      })
    ).rejects.toThrow();
    expect(ran).toBe(false);
  });

  it('fails closed on missing/unknown results and blocking findings', () => {
    const scannerBytes = Buffer.from('trusted-scanner-fixture');
    const digest = createHash('sha256').update(scannerBytes).digest('hex');
    const args = {
      policy: { scannerSha256Allowlist: [digest] },
      scannerBytes,
      blobs: [],
      scannerAvailable: true,
      completed: true,
      findingsKnown: true,
      blocked: false
    };
    expect(evaluateStageA({ ...args, completed: false }).result.status).toBe(
      'incomplete'
    );
    expect(evaluateStageA({ ...args, blocked: true }).result.status).toBe(
      'blocked'
    );
    expect(
      evaluateStageA({ ...args, findingsKnown: false }).result.status
    ).toBe('incomplete');
  });

  it('consumes a real approval once before running Stage B', async () => {
    const scannerBytes = Buffer.from('trusted-scanner-fixture');
    const digest = createHash('sha256').update(scannerBytes).digest('hex');
    const { result, approval } = evaluateStageA({
      policy: { scannerSha256Allowlist: [digest] },
      scannerBytes,
      blobs: [],
      scannerAvailable: true,
      completed: true,
      findingsKnown: true,
      blocked: false
    });
    expect(result.status).toBe('approved');
    if (!approval) throw new Error('expected an approval token');
    const action = vi.fn(async () => 'ran');
    expect(await runStageB(approval, action)).toBe('ran');
    await expect(runStageB(approval, action)).rejects.toThrow();
    expect(action).toHaveBeenCalledTimes(1);
  });
});
