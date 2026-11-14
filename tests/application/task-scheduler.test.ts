import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  AnalysisResultCache,
  MAX_ANALYSIS_CACHE_BYTES,
  MAX_ANALYSIS_CACHE_ENTRIES,
  MAX_ANALYSIS_CACHE_ENTRY_BYTES,
  MAX_ANALYSIS_TASK_CONCURRENCY,
  MAX_ANALYSIS_TASK_DEPENDENCIES,
  MAX_ANALYSIS_TASKS,
  runIncrementalTaskDag,
  runTaskDag
} from '../../src/application/task-scheduler.js';

describe('analysis DAG scheduler', () => {
  it('keeps cache configuration under hard retained-memory ceilings', () => {
    expect(
      () => new AnalysisResultCache(MAX_ANALYSIS_CACHE_ENTRIES + 1)
    ).toThrow('cache entry and byte budgets are invalid');
    expect(
      () =>
        new AnalysisResultCache(
          1,
          MAX_ANALYSIS_CACHE_BYTES + 1,
          MAX_ANALYSIS_CACHE_ENTRY_BYTES
        )
    ).toThrow('cache entry and byte budgets are invalid');
    expect(
      () =>
        new AnalysisResultCache(
          1,
          MAX_ANALYSIS_CACHE_BYTES,
          MAX_ANALYSIS_CACHE_ENTRY_BYTES + 1
        )
    ).toThrow('cache entry and byte budgets are invalid');
  });

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

  it('rejects invalid or unbounded task concurrency requests', async () => {
    const task = [{ id: 'single', run: async () => true }];
    for (const concurrency of [
      0,
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY
    ]) {
      await expect(runTaskDag(task, { concurrency })).rejects.toThrow(
        'analysis task concurrency must be an integer'
      );
    }
    await expect(
      runTaskDag(task, { concurrency: MAX_ANALYSIS_TASK_CONCURRENCY + 1 })
    ).rejects.toThrow(`from 1 to ${MAX_ANALYSIS_TASK_CONCURRENCY}`);
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

  it('schedules high fan-out and converging dependencies without recursion', async () => {
    const branches = Array.from(
      { length: 1_000 },
      (_, index) => `branch-${String(index).padStart(4, '0')}`
    );
    const highFanIn = await runTaskDag(
      [
        { id: 'root', run: async () => 'root' },
        ...branches.map((id) => ({
          id,
          dependsOn: ['root'],
          run: async () => id
        })),
        {
          id: 'aggregate',
          dependsOn: branches,
          run: async () => branches.length
        }
      ],
      { concurrency: 32 }
    );
    expect(highFanIn).toHaveLength(branches.length + 2);
    expect(highFanIn.at(-1)).toMatchObject({
      id: 'aggregate',
      state: 'complete',
      value: branches.length
    });

    const depth = 10_000;
    const deepChain = await runTaskDag(
      Array.from({ length: depth }, (_, index) => ({
        id: `chain-${String(index).padStart(5, '0')}`,
        ...(index === 0
          ? {}
          : {
              dependsOn: [`chain-${String(index - 1).padStart(5, '0')}`]
            }),
        run: async () => index
      })),
      { concurrency: 8 }
    );
    expect(deepChain).toHaveLength(depth);
    expect(deepChain.at(-1)).toMatchObject({
      id: 'chain-09999',
      state: 'complete',
      value: depth - 1
    });
  });

  it('cancels ready work without starting it', async () => {
    const controller = new AbortController();
    controller.abort();
    const result = await runTaskDag([{ id: 'a', run: async () => 1 }], {
      signal: controller.signal
    });
    expect(result[0]?.state).toBe('cancelled');
  });

  it('removes the caller cancellation listener after a completed graph', async () => {
    const controller = new AbortController();
    const addListener = vi.spyOn(controller.signal, 'addEventListener');
    const removeListener = vi.spyOn(controller.signal, 'removeEventListener');
    await runTaskDag([{ id: 'done', run: async () => true }], {
      signal: controller.signal
    });
    expect(addListener).toHaveBeenCalledOnce();
    expect(removeListener).toHaveBeenCalledOnce();
    addListener.mockRestore();
    removeListener.mockRestore();
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

  it('invalidates only the changed task and graph dependents', async () => {
    const cache = new AnalysisResultCache();
    const counts = { sourceA: 0, sourceB: 0, aggregate: 0 };
    const tasks = (aFingerprint: string) => [
      {
        id: 'source-a',
        version: '1',
        inputFingerprint: aFingerprint,
        run: async () => ({ digest: aFingerprint, value: ++counts.sourceA })
      },
      {
        id: 'source-b',
        version: '1',
        inputFingerprint: 'b:unchanged',
        run: async () => ++counts.sourceB
      },
      {
        id: 'aggregate',
        version: '1',
        inputFingerprint: 'aggregate-config-v1',
        dependsOn: ['source-a'],
        run: async () => ++counts.aggregate
      }
    ];

    const cold = await runIncrementalTaskDag('project-root', tasks('a:v1'), {
      cache
    });
    const warm = await runIncrementalTaskDag('project-root', tasks('a:v1'), {
      cache
    });
    const changed = await runIncrementalTaskDag('project-root', tasks('a:v2'), {
      cache
    });

    expect(warm).toEqual(cold);
    expect(changed.map((item) => item.state)).toEqual([
      'complete',
      'complete',
      'complete'
    ]);
    expect(counts).toEqual({ sourceA: 2, sourceB: 1, aggregate: 2 });
    expect(cache.metrics.hits).toBe(4);
  });

  it('reuses dependents when changed inputs produce the same exact output', async () => {
    const cache = new AnalysisResultCache();
    let sourceRuns = 0;
    let dependentRuns = 0;
    const graph = (fingerprint: string) => [
      {
        id: 'normalizer',
        version: '1',
        inputFingerprint: fingerprint,
        run: async () => {
          sourceRuns++;
          return { normalized: 'same' };
        }
      },
      {
        id: 'report',
        version: '1',
        inputFingerprint: 'report-config-v1',
        dependsOn: ['normalizer'],
        run: async () => ++dependentRuns
      }
    ];
    await runIncrementalTaskDag('project-root', graph('content:a'), { cache });
    const next = await runIncrementalTaskDag(
      'project-root',
      graph('content:b'),
      { cache }
    );
    expect(sourceRuns).toBe(2);
    expect(dependentRuns).toBe(1);
    expect(next[1]).toMatchObject({ state: 'complete', value: 1 });
  });

  it('recomputes a bounded dependency graph during an invalidation storm', async () => {
    const cache = new AnalysisResultCache(512, 1024 * 1024, 16 * 1024);
    const width = 128;
    let sourceRuns = 0;
    let aggregateRuns = 0;
    const tasks = (fingerprint: string) => {
      const sourceTasks = Array.from({ length: width }, (_, index) => ({
        id: `source-${index}`,
        version: '1',
        inputFingerprint: `${fingerprint}:${index}`,
        run: async () => {
          sourceRuns++;
          return `result-${fingerprint}-${index}`;
        }
      }));
      return [
        ...sourceTasks,
        {
          id: 'aggregate',
          version: '1',
          inputFingerprint: 'aggregate-v1',
          dependsOn: sourceTasks.map((task) => task.id),
          run: async () => {
            aggregateRuns++;
            return width;
          }
        }
      ];
    };

    const cold = await runIncrementalTaskDag('storm-project', tasks('a'), {
      cache,
      concurrency: 32
    });
    const warm = await runIncrementalTaskDag('storm-project', tasks('a'), {
      cache,
      concurrency: 32
    });
    const invalidated = await runIncrementalTaskDag(
      'storm-project',
      tasks('b'),
      { cache, concurrency: 32 }
    );

    expect(warm).toEqual(cold);
    expect(invalidated.every((item) => item.state === 'complete')).toBe(true);
    expect(sourceRuns).toBe(width * 2);
    expect(aggregateRuns).toBe(2);
    expect(cache.metrics.entries).toBeLessThanOrEqual(512);
    expect(cache.metrics.retainedBytes).toBeLessThanOrEqual(1024 * 1024);
  });

  it('skips serialization for huge output before allocating a cache copy', () => {
    const cache = new AnalysisResultCache(2, 256, 128);
    const digest = cache.setWithDigest(
      'scope',
      'large-output',
      '1',
      Buffer.alloc(1024 * 1024, 7)
    );
    expect(digest).toBeUndefined();
    expect(cache.size).toBe(0);
    expect(cache.retainedByteSize).toBe(0);
  });

  it('bounds preflight work for oversized nested output', () => {
    const cache = new AnalysisResultCache(2, 256, 128);
    const output = { values: Array.from({ length: 100_000 }, (_, i) => i) };

    expect(cache.setWithDigest('scope', 'large-tree', '1', output)).toBe(
      undefined
    );
    expect(cache.size).toBe(0);
    expect(cache.retainedByteSize).toBe(0);
  });

  it('does not invoke accessors while estimating cache output size', () => {
    const cache = new AnalysisResultCache(2, 256, 128);
    let invoked = false;
    const output = Object.defineProperty({}, 'value', {
      enumerable: true,
      get() {
        invoked = true;
        return 'sensitive';
      }
    });

    expect(cache.setWithDigest('scope', 'accessor', '1', output)).toBe(
      undefined
    );
    expect(invoked).toBe(false);
    expect(cache.size).toBe(0);
  });

  it('bounds result-cache entries and evicts the oldest key', () => {
    const cache = new AnalysisResultCache(1);
    cache.set('one', 'task', '1', 'first');
    cache.set('two', 'task', '1', 'second');
    expect(cache.size).toBe(1);
    expect(cache.has('one', 'task', '1')).toBe(false);
    expect(cache.get('two', 'task', '1')).toBe('second');
    expect(cache.metrics).toMatchObject({
      hits: 1,
      misses: 0,
      evictions: 1,
      entries: 1
    });
  });

  it('evicts corrupt serialized entries and treats them as cache misses', () => {
    const cache = new AnalysisResultCache();
    const values = (cache as unknown as { values: Map<string, Buffer> }).values;
    cache.set('snapshot', 'task', '1', 'temporary');
    values.set(
      ['snapshot', 'task', '1'].join('\0'),
      Buffer.alloc(cache.byteSize, 0)
    );

    expect(cache.get('snapshot', 'task', '1')).toBeUndefined();
    expect(cache.metrics).toMatchObject({
      hits: 0,
      misses: 1,
      evictions: 1,
      entries: 0,
      retainedSerializedBytes: 0
    });
  });

  it('recomputes a task after evicting a corrupt cached value', async () => {
    const cache = new AnalysisResultCache();
    const version = createHash('sha256')
      .update(
        JSON.stringify({
          version: '1',
          inputFingerprint: 'scope-input',
          dependencyDigests: []
        })
      )
      .digest('hex');
    cache.set('snapshot', 'task', version, 'temporary');
    const values = (cache as unknown as { values: Map<string, Buffer> }).values;
    values.set(
      ['snapshot', 'task', version].join('\0'),
      Buffer.alloc(cache.byteSize, 0)
    );
    let executions = 0;
    const outcomes = await runIncrementalTaskDag(
      'snapshot',
      [{ id: 'task', version: '1', run: async () => ++executions }],
      { cache }
    );

    expect(outcomes[0]).toMatchObject({ state: 'complete', value: 1 });
    expect(executions).toBe(1);
    expect(cache.metrics.evictions).toBe(1);
  });

  it('bounds retained cache bytes and skips individually oversized results', () => {
    const cache = new AnalysisResultCache(10, 100, 64);
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

  it('counts cache key bytes toward its retained budget and rejects huge keys', () => {
    const cache = new AnalysisResultCache(10, 128, 64, 24);
    cache.set('root', 'task-a', '1', 'small');
    expect(cache.metrics.retainedBytes).toBe(
      cache.metrics.retainedSerializedBytes + cache.metrics.retainedKeyBytes
    );
    expect(cache.retainedByteSize).toBeLessThanOrEqual(128);

    cache.set('root', 'x'.repeat(100), '1', 'not retained');
    expect(cache.has('root', 'x'.repeat(100), '1')).toBe(false);
    expect(cache.retainedByteSize).toBeLessThanOrEqual(128);
  });

  it('rejects oversized task and dependency lists before graph allocation', async () => {
    await expect(runTaskDag(Array(MAX_ANALYSIS_TASKS + 1))).rejects.toThrow(
      `analysis task count exceeds ${MAX_ANALYSIS_TASKS}`
    );
    const dependencyEntries = Array(MAX_ANALYSIS_TASK_DEPENDENCIES + 1).fill(
      'root'
    );
    await expect(
      runTaskDag([
        { id: 'root', run: async () => true },
        {
          id: 'bounded',
          dependsOn: dependencyEntries,
          run: async () => true
        }
      ])
    ).rejects.toThrow(
      `analysis dependency entries exceed ${MAX_ANALYSIS_TASK_DEPENDENCIES}`
    );
  });

  it('keeps shared cache writes safe across concurrent incremental scans', async () => {
    const cache = new AnalysisResultCache(8, 4_096, 1_024);
    let executions = 0;
    const tasks = [
      {
        id: 'source',
        version: '1',
        inputFingerprint: 'sha256:stable',
        run: async () => {
          executions++;
          await new Promise((resolve) => setTimeout(resolve, 2));
          return { findings: ['stable'] };
        }
      },
      {
        id: 'report',
        version: '1',
        inputFingerprint: 'config:v1',
        dependsOn: ['source'],
        run: async () => ({ count: 1 })
      }
    ];
    const [left, right] = await Promise.all([
      runIncrementalTaskDag('project', tasks, { cache }),
      runIncrementalTaskDag('project', tasks, { cache })
    ]);

    expect(left).toEqual(right);
    expect(left.map((item) => item.state)).toEqual(['complete', 'complete']);
    expect(executions).toBeGreaterThanOrEqual(1);
    expect(executions).toBeLessThanOrEqual(2);
    expect(cache.size).toBeLessThanOrEqual(2);
    expect(cache.retainedByteSize).toBeLessThanOrEqual(4_096);
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
