import { deserialize, serialize } from 'node:v8';
import { MAX_CONCURRENT_OPERATIONS } from './concurrency.js';

export const MAX_ANALYSIS_TASK_CONCURRENCY = MAX_CONCURRENT_OPERATIONS;

export type AnalysisTask<T> = Readonly<{
  id: string;
  dependsOn?: readonly string[];
  run: (signal: AbortSignal) => Promise<T>;
}>;

export type TaskOutcome<T> =
  | { id: string; state: 'complete'; value: T }
  | { id: string; state: 'failed'; error: string }
  | { id: string; state: 'blocked' | 'cancelled'; reason: string };

/** FIFO cache scoped by a snapshot, with process-wide and per-entry byte limits. */
export class AnalysisResultCache {
  private readonly values = new Map<string, Buffer>();
  private currentBytes = 0;
  private cacheHits = 0;
  private cacheMisses = 0;
  private cacheEvictions = 0;

  constructor(
    private readonly maxEntries = 10_000,
    private readonly maxBytes = 64 * 1024 * 1024,
    private readonly maxEntryBytes = 4 * 1024 * 1024
  ) {
    if (
      !Number.isSafeInteger(maxEntries) ||
      maxEntries < 1 ||
      !Number.isSafeInteger(maxBytes) ||
      maxBytes < 1 ||
      !Number.isSafeInteger(maxEntryBytes) ||
      maxEntryBytes < 1 ||
      maxEntryBytes > maxBytes
    )
      throw new Error('cache entry and byte budgets are invalid');
  }

  get<T>(
    snapshotId: string,
    taskId: string,
    taskVersion: string
  ): T | undefined {
    const key = cacheKey(snapshotId, taskId, taskVersion);
    const value = this.values.get(key);
    if (value === undefined) {
      this.cacheMisses++;
      return undefined;
    }
    try {
      const decoded = deserialize(value) as T;
      this.cacheHits++;
      return decoded;
    } catch {
      this.values.delete(key);
      this.currentBytes -= value.byteLength;
      this.cacheEvictions++;
      this.cacheMisses++;
      return undefined;
    }
  }

  has(snapshotId: string, taskId: string, taskVersion: string): boolean {
    return this.values.has(cacheKey(snapshotId, taskId, taskVersion));
  }

  set<T>(
    snapshotId: string,
    taskId: string,
    taskVersion: string,
    value: T
  ): void {
    const key = cacheKey(snapshotId, taskId, taskVersion);
    const forgetPrevious = (): void => {
      const previous = this.values.get(key);
      if (!previous) return;
      this.values.delete(key);
      this.currentBytes -= previous.byteLength;
      this.cacheEvictions++;
    };
    let encoded: Buffer;
    try {
      encoded = serialize(value);
    } catch {
      forgetPrevious();
      return;
    }
    if (encoded.byteLength > this.maxEntryBytes) {
      forgetPrevious();
      return;
    }
    const previous = this.values.get(key);
    if (previous) this.currentBytes -= previous.byteLength;
    this.values.set(key, encoded);
    this.currentBytes += encoded.byteLength;
    while (
      this.values.size > this.maxEntries ||
      this.currentBytes > this.maxBytes
    ) {
      const oldest = this.values.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      const evicted = this.values.get(oldest);
      this.values.delete(oldest);
      if (evicted) {
        this.currentBytes -= evicted.byteLength;
        this.cacheEvictions++;
      }
    }
  }

  get size(): number {
    return this.values.size;
  }

  get byteSize(): number {
    return this.currentBytes;
  }

  get metrics(): Readonly<{
    hits: number;
    misses: number;
    evictions: number;
    entries: number;
    retainedSerializedBytes: number;
  }> {
    return Object.freeze({
      hits: this.cacheHits,
      misses: this.cacheMisses,
      evictions: this.cacheEvictions,
      entries: this.values.size,
      retainedSerializedBytes: this.currentBytes
    });
  }
}

function cacheKey(snapshotId: string, taskId: string, version: string): string {
  if (
    [snapshotId, taskId, version].some((part) => !part || part.includes('\0'))
  )
    throw new Error(
      'cache key components must be non-empty and cannot contain NUL'
    );
  return `${snapshotId}\0${taskId}\0${version}`;
}

function queuePush(queue: string[], value: string): void {
  let index = queue.length;
  queue.push(value);
  while (index > 0) {
    const parent = Math.floor((index - 1) / 2);
    const parentValue = queue[parent];
    if (parentValue === undefined || parentValue <= value) break;
    queue[index] = parentValue;
    index = parent;
  }
  queue[index] = value;
}

function queuePop(queue: string[]): string | undefined {
  const first = queue[0];
  const last = queue.pop();
  if (first === undefined || last === undefined || queue.length === 0)
    return first;
  let index = 0;
  while (true) {
    const left = index * 2 + 1;
    if (left >= queue.length) break;
    const right = left + 1;
    const child =
      right < queue.length && (queue[right] ?? '') < (queue[left] ?? '')
        ? right
        : left;
    const childValue = queue[child];
    if (childValue === undefined || last <= childValue) break;
    queue[index] = childValue;
    index = child;
  }
  queue[index] = last;
  return first;
}

/**
 * Executes an analysis DAG with deterministic output and bounded concurrency.
 * Validation and graph construction are O(V+E); scheduling is O((V+E) log V)
 * from the lexicographic ready-queue heap, plus task work W. Memory is
 * O(V+E+C), including outcomes and the ready queue.
 */
export async function runTaskDag<T>(
  tasks: readonly AnalysisTask<T>[],
  options: { concurrency?: number; signal?: AbortSignal } = {}
): Promise<TaskOutcome<T>[]> {
  const requestedConcurrency = options.concurrency ?? 4;
  if (
    !Number.isSafeInteger(requestedConcurrency) ||
    requestedConcurrency < 1 ||
    requestedConcurrency > MAX_ANALYSIS_TASK_CONCURRENCY
  )
    throw new RangeError(
      `analysis task concurrency must be an integer from 1 to ${MAX_ANALYSIS_TASK_CONCURRENCY}`
    );
  const limit = requestedConcurrency;
  const byId = new Map<string, AnalysisTask<T>>();
  for (const task of tasks) {
    if (!task.id || byId.has(task.id))
      throw new Error(`duplicate or empty task id: ${task.id}`);
    byId.set(task.id, task);
  }
  const remaining = new Map<string, number>();
  const dependents = new Map<string, string[]>();
  for (const task of tasks) {
    const dependencies = new Set(task.dependsOn ?? []);
    for (const dependency of dependencies) {
      if (!byId.has(dependency))
        throw new Error(`unknown dependency ${dependency} for ${task.id}`);
      const next = dependents.get(dependency) ?? [];
      next.push(task.id);
      dependents.set(dependency, next);
    }
    remaining.set(task.id, dependencies.size);
  }
  const queue: string[] = [];
  for (const task of tasks)
    if (remaining.get(task.id) === 0) queuePush(queue, task.id);
  const outcomes = new Map<string, TaskOutcome<T>>();
  const started = new Set<string>();
  const controller = new AbortController();
  const abort = () => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener('abort', abort, { once: true });

  const finish = (outcome: TaskOutcome<T>) => {
    outcomes.set(outcome.id, outcome);
    for (const id of dependents.get(outcome.id) ?? []) {
      remaining.set(id, (remaining.get(id) ?? 1) - 1);
      if (remaining.get(id) === 0) queuePush(queue, id);
    }
  };
  try {
    let active = 0;
    await new Promise<void>((resolve) => {
      const pump = () => {
        if (controller.signal.aborted) {
          for (const task of tasks)
            if (!started.has(task.id) && !outcomes.has(task.id))
              finish({
                id: task.id,
                state: 'cancelled',
                reason: 'analysis cancelled'
              });
          // Running tasks receive the abort signal, but may need to clean up
          // before the scheduler can safely return. Wait for every worker.
          if (active === 0) resolve();
          return;
        }
        while (active < limit && queue.length) {
          const id = queuePop(queue);
          if (id === undefined) break;
          const task = byId.get(id);
          if (!task) continue;
          const blockedBy = (task.dependsOn ?? []).find(
            (dependency) => outcomes.get(dependency)?.state !== 'complete'
          );
          if (blockedBy) {
            finish({
              id,
              state: 'blocked',
              reason: `dependency ${blockedBy} did not complete`
            });
            continue;
          }
          active++;
          started.add(id);
          void Promise.resolve()
            .then(() => task.run(controller.signal))
            .then(
              (value) =>
                finish(
                  controller.signal.aborted
                    ? {
                        id,
                        state: 'cancelled',
                        reason: 'analysis cancelled before task completion'
                      }
                    : { id, state: 'complete', value }
                ),
              (error: unknown) =>
                finish(
                  controller.signal.aborted
                    ? {
                        id,
                        state: 'cancelled',
                        reason: 'analysis cancelled while task was running'
                      }
                    : {
                        id,
                        state: 'failed',
                        error:
                          error instanceof Error ? error.message : String(error)
                      }
                )
            )
            .finally(() => {
              active--;
              pump();
            });
        }
        if (active === 0 && controller.signal.aborted) {
          pump();
          return;
        }
        if (active === 0 && queue.length === 0) {
          // Any remaining nodes imply a cycle; report it explicitly.
          for (const task of tasks)
            if (!outcomes.has(task.id))
              finish({
                id: task.id,
                state: 'blocked',
                reason: 'dependency cycle'
              });
          resolve();
        }
      };
      pump();
    });
  } finally {
    options.signal?.removeEventListener('abort', abort);
  }
  return tasks.map((task) => {
    const outcome = outcomes.get(task.id);
    if (!outcome)
      throw new Error(`task ${task.id} did not reach a terminal state`);
    return outcome;
  });
}

/** Reuses only successful task results for the same snapshot and task version. */
export async function runIncrementalTaskDag<T>(
  snapshotId: string,
  tasks: readonly (AnalysisTask<T> & { version: string })[],
  options: {
    concurrency?: number;
    signal?: AbortSignal;
    cache: AnalysisResultCache;
  }
): Promise<TaskOutcome<T>[]> {
  if (!snapshotId)
    throw new Error('snapshot id is required for cached analysis');
  const wrapped = tasks.map((task) => ({
    ...task,
    run: async (signal: AbortSignal): Promise<T> => {
      if (options.cache.has(snapshotId, task.id, task.version)) {
        const cached = options.cache.get<T>(snapshotId, task.id, task.version);
        // `undefined` can be a valid serialized task value. A second has()
        // distinguishes it from a corrupt entry that get() evicted.
        if (
          cached !== undefined ||
          options.cache.has(snapshotId, task.id, task.version)
        )
          return cached as T;
      }
      const value = await task.run(signal);
      if (!signal.aborted)
        options.cache.set(snapshotId, task.id, task.version, value);
      return value;
    }
  }));
  return runTaskDag(wrapped, options);
}
