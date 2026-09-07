import { describe, expect, it } from 'vitest';
import { AnalyzerRunner } from '../../src/application/analyzer-runner.js';
import { mapConcurrent } from '../../src/application/concurrency.js';
import type { Analyzer } from '../../src/contracts/analyzer.js';

function analyzer(
  id: string,
  analyze: Analyzer['analyze']
): Analyzer {
  return { id, version: '1.0.0', analyze };
}

describe('AnalyzerRunner', () => {
  it('enforces a hard deadline even when an analyzer ignores abort', async () => {
    const never = analyzer('never', () => new Promise(() => undefined));
    const startedAt = performance.now();

    const [result] = await new AnalyzerRunner({
      concurrency: 1,
      timeoutMs: 20
    }).run([never], { root: process.cwd() });

    expect(result?.status).toBe('timed_out');
    expect(result?.findings).toEqual([]);
    expect(performance.now() - startedAt).toBeLessThan(500);
  });

  it('isolates one analyzer failure from successful siblings', async () => {
    const failed = analyzer('failed', async () => {
      throw new Error('boom');
    });
    const healthy = analyzer('healthy', async () => ({
      analyzer: 'healthy',
      durationMs: 0,
      findings: []
    }));

    const results = await new AnalyzerRunner({ concurrency: 2 }).run(
      [failed, healthy],
      { root: process.cwd() }
    );

    expect(results.map((result) => result.status)).toEqual([
      'failed',
      'ok'
    ]);
    expect(results[0]?.error).toBe('boom');
  });

  it('preserves input order regardless of completion order', async () => {
    const slow = analyzer('slow', async () => {
      await new Promise((resolve) => setTimeout(resolve, 30));
      return { analyzer: 'slow', durationMs: 0, findings: [] };
    });
    const fast = analyzer('fast', async () => ({
      analyzer: 'fast',
      durationMs: 0,
      findings: []
    }));

    const results = await new AnalyzerRunner({ concurrency: 2 }).run(
      [slow, fast],
      { root: process.cwd() }
    );

    expect(results.map((result) => result.analyzer)).toEqual([
      'slow',
      'fast'
    ]);
  });

  it('returns cancellation even for a non-cooperative analyzer', async () => {
    const controller = new AbortController();
    const never = analyzer('never', () => new Promise(() => undefined));
    setTimeout(() => controller.abort(), 10);

    const [result] = await new AnalyzerRunner({
      concurrency: 1,
      timeoutMs: 5_000
    }).run([never], {
      root: process.cwd(),
      signal: controller.signal
    });

    expect(result?.status).toBe('cancelled');
  });
});

describe('mapConcurrent', () => {
  it('never exceeds its configured concurrency and keeps order', async () => {
    let active = 0;
    let peak = 0;

    const results = await mapConcurrent(
      [1, 2, 3, 4, 5, 6],
      2,
      async (value) => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 10));
        active -= 1;
        return value * 2;
      }
    );

    expect(peak).toBe(2);
    expect(results).toEqual([2, 4, 6, 8, 10, 12]);
  });
});
