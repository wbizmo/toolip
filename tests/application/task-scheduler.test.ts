import { describe, expect, it } from 'vitest';
import {
  AnalysisResultCache,
  runIncrementalTaskDag,
  runTaskDag
} from '../../src/application/task-scheduler.js';

describe('analysis DAG scheduler', () => {
  it('respects dependencies, bounds concurrency, and returns input order', async () => {
    let active = 0;
    let peak = 0;
    const run = async (value: number) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 2));
      active--;
      return value;
    };
    const result = await runTaskDag(
      [
        { id: 'c', dependsOn: ['a'], run: () => run(3) },
        { id: 'a', run: () => run(1) },
        { id: 'b', run: () => run(2) }
      ],
      { concurrency: 2 }
    );
    expect(result.map((item) => item.id)).toEqual(['c', 'a', 'b']);
    expect(result.map((item) => item.state)).toEqual([
      'complete',
      'complete',
      'complete'
    ]);
    expect(peak).toBeLessThanOrEqual(2);
  });

  it('blocks dependents after failure and reports cycles', async () => {
    const cycle = await runTaskDag([
      { id: 'a', dependsOn: ['b'], run: async () => 1 },
      { id: 'b', dependsOn: ['a'], run: async () => 2 }
    ]);
    expect(cycle.every((item) => item.state === 'blocked')).toBe(true);
    const failed = await runTaskDag([
      {
        id: 'a',
        run: async () => {
          throw new Error('no');
        }
      },
      { id: 'b', dependsOn: ['a'], run: async () => 2 }
    ]);
    expect(failed.map((item) => item.state)).toEqual(['failed', 'blocked']);
  });

  it('cancels ready work without starting it', async () => {
    const controller = new AbortController();
    controller.abort();
    const result = await runTaskDag([{ id: 'a', run: async () => 1 }], {
      signal: controller.signal
    });
    expect(result[0]?.state).toBe('cancelled');
  });

  it('aborts active work and waits for its cleanup before returning', async () => {
    const controller = new AbortController();
    let cleaned = false;
    const pending = runTaskDag(
      [
        {
          id: 'active',
          run: async (signal) => {
            await new Promise<void>((resolve) => {
              signal.addEventListener('abort', () => resolve(), { once: true });
            });
            await new Promise((resolve) => setTimeout(resolve, 5));
            cleaned = true;
            throw new Error('cancelled during cleanup');
          }
        },
        { id: 'queued', run: async () => 'must not start' }
      ],
      { concurrency: 1, signal: controller.signal }
    );
    await new Promise((resolve) => setTimeout(resolve, 1));
    controller.abort();
    const result = await pending;
    expect(cleaned).toBe(true);
    expect(result.map((item) => item.state)).toEqual([
      'cancelled',
      'cancelled'
    ]);
  });

  it('discards a late task result after cancellation and does not cache it', async () => {
    const controller = new AbortController();
    const cache = new AnalysisResultCache();
    const task = {
      id: 'late-result',
      version: '1',
      run: async (signal: AbortSignal) =>
        await new Promise<number>((resolve) => {
          signal.addEventListener('abort', () => resolve(42), { once: true });
        })
    };
    const pending = runIncrementalTaskDag('snapshot', [task], {
      cache,
      signal: controller.signal
    });

    await new Promise((resolve) => setTimeout(resolve, 1));
    controller.abort();
    const result = await pending;

    expect(result).toEqual([
      {
        id: 'late-result',
        state: 'cancelled',
        reason: 'analysis cancelled before task completion'
      }
    ]);
    expect(cache.has('snapshot', 'late-result', '1')).toBe(false);
  });

  it('captures synchronous task exceptions as task failures', async () => {
    const result = await runTaskDag([
      {
        id: 'sync-failure',
        run: () => {
          throw new Error('synchronous failure');
        }
      }
    ]);
    expect(result).toEqual([
      { id: 'sync-failure', state: 'failed', error: 'synchronous failure' }
    ]);
  });

  it('reuses only results with matching snapshot and analyzer version', async () => {
    const cache = new AnalysisResultCache(2);
    let executions = 0;
    const task = {
      id: 'source-analysis',
      version: '2',
      run: async () => ++executions
    };
    await runIncrementalTaskDag('snapshot-a', [task], { cache });
    const cached = await runIncrementalTaskDag('snapshot-a', [task], { cache });
    expect(cached[0]).toMatchObject({ state: 'complete', value: 1 });
    expect(executions).toBe(1);
    await runIncrementalTaskDag('snapshot-b', [task], { cache });
    expect(executions).toBe(2);
    await runIncrementalTaskDag('snapshot-b', [{ ...task, version: '3' }], {
      cache
    });
    expect(executions).toBe(3);
  });

  it('bounds result-cache entries and evicts the oldest key', () => {
    const cache = new AnalysisResultCache(1);
    cache.set('one', 'task', '1', 'first');
    cache.set('two', 'task', '1', 'second');
    expect(cache.size).toBe(1);
    expect(cache.has('one', 'task', '1')).toBe(false);
    expect(cache.get('two', 'task', '1')).toBe('second');
  });

  it('bounds retained cache bytes and skips individually oversized results', () => {
    const cache = new AnalysisResultCache(10, 80, 64);
    cache.set('oldest', 'task', '1', 'a'.repeat(28));
    cache.set('middle', 'task', '1', 'b'.repeat(28));
    cache.set('newest', 'task', '1', 'c'.repeat(28));
    expect(cache.byteSize).toBeLessThanOrEqual(80);
    expect(cache.has('oldest', 'task', '1')).toBe(false);
    expect(cache.has('middle', 'task', '1')).toBe(true);
    expect(cache.has('newest', 'task', '1')).toBe(true);

    const sizeBeforeOversizedValue = cache.size;
    cache.set('oversized', 'task', '1', 'x'.repeat(100));
    expect(cache.size).toBe(sizeBeforeOversizedValue);
    expect(cache.has('oversized', 'task', '1')).toBe(false);

    cache.set('replace', 'task', '1', 'small');
    cache.set('replace', 'task', '1', 'y'.repeat(100));
    expect(cache.has('replace', 'task', '1')).toBe(false);
  });

  it('copies mutable cache values and preserves FIFO order on replacement', () => {
    const cache = new AnalysisResultCache(2);
    cache.set('one', 'task', '1', { findings: ['original'] });
    cache.set('two', 'task', '1', 'second');
    const copy = cache.get<{ findings: string[] }>('one', 'task', '1');
    copy?.findings.push('caller mutation');
    expect(cache.get('one', 'task', '1')).toEqual({
      findings: ['original']
    });

    cache.set('one', 'task', '1', { findings: ['replacement'] });
    cache.set('three', 'task', '1', 'third');
    expect(cache.has('one', 'task', '1')).toBe(false);
    expect(cache.has('two', 'task', '1')).toBe(true);
  });
});
