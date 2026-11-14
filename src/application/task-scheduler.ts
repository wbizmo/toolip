import { createHash } from 'node:crypto';
import { deserialize, serialize } from 'node:v8';
import { MAX_CONCURRENT_OPERATIONS } from './concurrency.js';

export const MAX_ANALYSIS_TASK_CONCURRENCY = MAX_CONCURRENT_OPERATIONS;
export const MAX_ANALYSIS_TASKS = 100_000;
export const MAX_ANALYSIS_TASK_DEPENDENCIES = 1_000_000;
export const MAX_ANALYSIS_TASK_METADATA_BYTES = 16 * 1024 * 1024;
export const MAX_ANALYSIS_CACHE_ENTRIES = 100_000;
export const MAX_ANALYSIS_CACHE_BYTES = 64 * 1024 * 1024;
export const MAX_ANALYSIS_CACHE_ENTRY_BYTES = 4 * 1024 * 1024;
const defaultAnalysisCacheEntries = 10_000;
const maximumTaskIdBytes = 1_024;
const maximumCacheKeyBytes = 1_024;
const maximumTaskVersionBytes = 1_024;
const maximumTaskInputFingerprintBytes = 4_096;

/**
 * Estimate a conservative upper bound before V8 serialization allocates a
 * second copy of an output. Values that cannot be safely estimated are left
 * uncached; callers still receive their original result.
 */
function estimateCacheValueBytes(value: unknown, limit: number): number | undefined {
  const pending: unknown[] = [value];
  const visited = new Set<object>();
  let bytes = 16;
  const add = (amount: number): boolean => {
    bytes += amount;
    return bytes <= limit;
  };

  while (pending.length > 0) {
    const current = pending.pop();
    if (current === null || current === undefined) {
      if (!add(16)) return undefined;
      continue;
    }
    switch (typeof current) {
      case 'boolean':
      case 'number':
      case 'bigint':
        if (!add(16)) return undefined;
        continue;
      case 'string':
        if (!add(Buffer.byteLength(current, 'utf8') * 2 + 8))
          return undefined;
        continue;
      case 'object':
        break;
      default:
        return undefined;
    }

    const object = current as object;
    if (visited.has(object)) continue;
    visited.add(object);
    if (Buffer.isBuffer(object)) {
      if (!add(object.byteLength * 2 + 32)) return undefined;
      continue;
    }
    if (ArrayBuffer.isView(object)) {
      if (!add(object.byteLength * 2 + 32)) return undefined;
      continue;
    }
    if (object instanceof ArrayBuffer) {
      if (!add(object.byteLength * 2 + 32)) return undefined;
      continue;
    }
    if (object instanceof Map) {
      if (!add(32)) return undefined;
      for (const [key, item] of object) {
        if (!add(32)) return undefined;
        pending.push(key, item);
      }
      continue;
    }
    if (object instanceof Set) {
      if (!add(32)) return undefined;
      for (const item of object) {
        if (!add(32)) return undefined;
        pending.push(item);
      }
      continue;
    }
    if (Array.isArray(object)) {
      if (object.length > Math.floor(limit / 32) || !add(object.length * 32))
        return undefined;
      for (let index = 0; index < object.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(object, index);
        if (!descriptor) continue;
        if (!('value' in descriptor)) return undefined;
        pending.push(descriptor.value);
      }
      // Reject named array properties without materializing a key array.
      for (const key in object) {
        if (!Object.hasOwn(object, key)) continue;
        if (
          !/^(?:0|[1-9]\d*)$/u.test(key) ||
          Number(key) >= object.length
        )
          return undefined;
      }
      continue;
    }
    if (Object.getPrototypeOf(object) !== Object.prototype &&
        Object.getPrototypeOf(object) !== null) {
      // Dates, errors, class instances and host objects have serialization
      // rules that this small estimator cannot bound reliably.
      return undefined;
    }
    if (!add(32)) return undefined;
    for (const key in object) {
      if (!Object.hasOwn(object, key)) continue;
      if (!add(Buffer.byteLength(key, 'utf8') * 2 + 16)) return undefined;
      const descriptor = Object.getOwnPropertyDescriptor(object, key);
      if (!descriptor) continue;
      if (!('value' in descriptor)) return undefined;
      pending.push(descriptor.value);
    }
  }
  return bytes;
}

export type AnalysisTask<T> = Readonly<{
  id: string;
  dependsOn?: readonly string[];
  /** Content/config identity for this task; omit only when the whole snapshot is an input. */
  inputFingerprint?: string;
  run: (signal: AbortSignal) => Promise<T>;
}>;

export type TaskOutcome<T> =
  | { id: string; state: 'complete'; value: T }
  | { id: string; state: 'failed'; error: string }
  | { id: string; state: 'blocked' | 'cancelled'; reason: string };

/** FIFO cache with bounded payload, key, entry count and corrupt-entry recovery. */
export class AnalysisResultCache {
  private readonly values = new Map<string, Buffer>();
  private currentBytes = 0;
  private currentKeyBytes = 0;
  private cacheHits = 0;
  private cacheMisses = 0;
  private cacheEvictions = 0;

  constructor(
    private readonly maxEntries = defaultAnalysisCacheEntries,
    private readonly maxBytes = MAX_ANALYSIS_CACHE_BYTES,
    private readonly maxEntryBytes = MAX_ANALYSIS_CACHE_ENTRY_BYTES,
    private readonly maxKeyBytes = maximumCacheKeyBytes
  ) {
    if (
      !Number.isSafeInteger(maxEntries) ||
      maxEntries < 1 ||
      maxEntries > MAX_ANALYSIS_CACHE_ENTRIES ||
      !Number.isSafeInteger(maxBytes) ||
      maxBytes < 1 ||
      maxBytes > MAX_ANALYSIS_CACHE_BYTES ||
      !Number.isSafeInteger(maxEntryBytes) ||
      maxEntryBytes < 1 ||
      maxEntryBytes > MAX_ANALYSIS_CACHE_ENTRY_BYTES ||
      maxEntryBytes > maxBytes ||
      !Number.isSafeInteger(maxKeyBytes) ||
      maxKeyBytes < 1 ||
      maxKeyBytes > maximumCacheKeyBytes
    )
      throw new Error('cache entry and byte budgets are invalid');
  }

  get<T>(
    snapshotId: string,
    taskId: string,
    taskVersion: string
  ): T | undefined {
    const result = this.read<T>(snapshotId, taskId, taskVersion);
    return result.found ? result.value : undefined;
  }

  /** Reads a value and its exact serialized digest in one cache operation. */
  read<T>(
    snapshotId: string,
    taskId: string,
    taskVersion: string
  ): { found: true; value: T; digest: string } | { found: false } {
    const key = cacheKey(snapshotId, taskId, taskVersion);
    if (
      key === undefined ||
      Buffer.byteLength(key, 'utf8') > this.maxKeyBytes
    ) {
      this.cacheMisses++;
      return { found: false };
    }
    const value = this.values.get(key);
    if (value === undefined) {
      this.cacheMisses++;
      return { found: false };
    }
    try {
      const decoded = deserialize(value) as T;
      this.cacheHits++;
      return {
        found: true,
        value: decoded,
        digest: createHash('sha256').update(value).digest('hex')
      };
    } catch {
      this.values.delete(key);
      this.currentBytes -= value.byteLength;
      this.currentKeyBytes -= Buffer.byteLength(key, 'utf8');
      this.cacheEvictions++;
      this.cacheMisses++;
      return { found: false };
    }
  }

  has(snapshotId: string, taskId: string, taskVersion: string): boolean {
    const key = cacheKey(snapshotId, taskId, taskVersion);
    return (
      key !== undefined &&
      Buffer.byteLength(key, 'utf8') <= this.maxKeyBytes &&
      this.values.has(key)
    );
  }

  set<T>(
    snapshotId: string,
    taskId: string,
    taskVersion: string,
    value: T
  ): void {
    this.setWithDigest(snapshotId, taskId, taskVersion, value);
  }

  /** Stores a value and returns its digest even when the size cap skips storage. */
  setWithDigest<T>(
    snapshotId: string,
    taskId: string,
    taskVersion: string,
    value: T
  ): string | undefined {
    const key = cacheKey(snapshotId, taskId, taskVersion);
    if (key === undefined) return undefined;
    const keyBytes = Buffer.byteLength(key, 'utf8');
    const forgetPrevious = (): void => {
      const previous = this.values.get(key);
      if (!previous) return;
      this.values.delete(key);
      this.currentBytes -= previous.byteLength;
      this.currentKeyBytes -= keyBytes;
      this.cacheEvictions++;
    };
    if (keyBytes > this.maxKeyBytes) {
      forgetPrevious();
      return undefined;
    }
    let encoded: Buffer;
    // Serialization itself materializes the complete output. Preflight against
    // a hard 2x-entry transient allocation ceiling before making that copy.
    if (estimateCacheValueBytes(value, this.maxEntryBytes * 2) === undefined) {
      forgetPrevious();
      return undefined;
    }
    try {
      encoded = serialize(value);
    } catch {
      forgetPrevious();
      return undefined;
    }
    const digest = createHash('sha256').update(encoded).digest('hex');
    if (
      encoded.byteLength > this.maxEntryBytes ||
      encoded.byteLength + keyBytes > this.maxBytes
    ) {
      forgetPrevious();
      return digest;
    }
    const previous = this.values.get(key);
    if (previous) {
      this.currentBytes -= previous.byteLength;
      this.currentKeyBytes -= keyBytes;
    }
    this.values.set(key, encoded);
    this.currentBytes += encoded.byteLength;
    this.currentKeyBytes += keyBytes;
    while (
      this.values.size > this.maxEntries ||
      this.currentBytes + this.currentKeyBytes > this.maxBytes
    ) {
      const oldest = this.values.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      const evicted = this.values.get(oldest);
      this.values.delete(oldest);
      if (evicted) {
        this.currentBytes -= evicted.byteLength;
        this.currentKeyBytes -= Buffer.byteLength(oldest, 'utf8');
        this.cacheEvictions++;
      }
    }
    return digest;
  }

  get size(): number {
    return this.values.size;
  }

  get byteSize(): number {
    return this.currentBytes;
  }

  get retainedByteSize(): number {
    return this.currentBytes + this.currentKeyBytes;
  }

  get metrics(): Readonly<{
    hits: number;
    misses: number;
    evictions: number;
    entries: number;
    retainedSerializedBytes: number;
    retainedKeyBytes: number;
    retainedBytes: number;
  }> {
    return Object.freeze({
      hits: this.cacheHits,
      misses: this.cacheMisses,
      evictions: this.cacheEvictions,
      entries: this.values.size,
      retainedSerializedBytes: this.currentBytes,
      retainedKeyBytes: this.currentKeyBytes,
      retainedBytes: this.retainedByteSize
    });
  }
}

function cacheKey(
  snapshotId: string,
  taskId: string,
  version: string
): string | undefined {
  if (
    [snapshotId, taskId, version].some((part) => !part || part.includes('\0'))
  )
    throw new Error(
      'cache key components must be non-empty and cannot contain NUL'
    );
  const key = `${snapshotId}\0${taskId}\0${version}`;
  return Buffer.byteLength(key, 'utf8') <= maximumCacheKeyBytes
    ? key
    : undefined;
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
 * O(V+E+C+R), including outcomes R retained task-result bytes and the ready
 * queue. The graph is capped at 100,000 tasks, 1,000,000 dependency entries,
 * 16 MiB of ID metadata, 1 KiB per task ID and 32 active tasks.
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
  if (tasks.length > MAX_ANALYSIS_TASKS)
    throw new RangeError(`analysis task count exceeds ${MAX_ANALYSIS_TASKS}`);
  const byId = new Map<string, AnalysisTask<T>>();
  let metadataBytes = 0;
  for (const task of tasks) {
    if (!task || typeof task !== 'object')
      throw new TypeError('analysis task entries must be objects');
    if (
      typeof task.id !== 'string' ||
      !task.id ||
      Buffer.byteLength(task.id, 'utf8') > maximumTaskIdBytes ||
      byId.has(task.id)
    )
      throw new Error(`invalid, oversized, or duplicate task id: ${task.id}`);
    metadataBytes += Buffer.byteLength(task.id, 'utf8');
    if (metadataBytes > MAX_ANALYSIS_TASK_METADATA_BYTES)
      throw new RangeError(
        `analysis task metadata exceeds ${MAX_ANALYSIS_TASK_METADATA_BYTES} bytes`
      );
    byId.set(task.id, task);
  }
  const remaining = new Map<string, number>();
  const dependents = new Map<string, string[]>();
  let dependencyCount = 0;
  for (const task of tasks) {
    if (task.dependsOn !== undefined && !Array.isArray(task.dependsOn))
      throw new TypeError(`dependencies for ${task.id} must be an array`);
    dependencyCount += task.dependsOn?.length ?? 0;
    if (dependencyCount > MAX_ANALYSIS_TASK_DEPENDENCIES)
      throw new RangeError(
        `analysis dependency entries exceed ${MAX_ANALYSIS_TASK_DEPENDENCIES}`
      );
    for (const dependency of task.dependsOn ?? []) {
      if (
        typeof dependency !== 'string' ||
        !dependency ||
        Buffer.byteLength(dependency, 'utf8') > maximumTaskIdBytes
      )
        throw new Error(`invalid dependency task id for ${task.id}`);
      metadataBytes += Buffer.byteLength(dependency, 'utf8');
      if (metadataBytes > MAX_ANALYSIS_TASK_METADATA_BYTES)
        throw new RangeError(
          `analysis task metadata exceeds ${MAX_ANALYSIS_TASK_METADATA_BYTES} bytes`
        );
    }
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

/**
 * Reuses successful task results by stable cache scope, task version, explicit
 * input fingerprint, and the exact serialized outputs of graph dependencies.
 * Changing one input invalidates its task; dependents invalidate only when
 * that task's output bytes change.
 */
export async function runIncrementalTaskDag<T>(
  cacheScope: string,
  tasks: readonly (AnalysisTask<T> & { version: string })[],
  options: {
    concurrency?: number;
    signal?: AbortSignal;
    cache: AnalysisResultCache;
  }
): Promise<TaskOutcome<T>[]> {
  if (typeof cacheScope !== 'string' || !cacheScope)
    throw new Error('cache scope is required for incremental analysis');
  if (tasks.length > MAX_ANALYSIS_TASKS)
    throw new RangeError(`analysis task count exceeds ${MAX_ANALYSIS_TASKS}`);
  let fingerprintMetadataBytes = 0;
  for (const task of tasks) {
    if (
      typeof task.version !== 'string' ||
      !task.version ||
      Buffer.byteLength(task.version, 'utf8') > maximumTaskVersionBytes
    )
      throw new Error(`invalid or oversized version for task ${task.id}`);
    if (
      task.inputFingerprint !== undefined &&
      (typeof task.inputFingerprint !== 'string' ||
        !task.inputFingerprint ||
        Buffer.byteLength(task.inputFingerprint, 'utf8') >
          maximumTaskInputFingerprintBytes)
    )
      throw new Error(
        `invalid or oversized input fingerprint for task ${task.id}`
      );
    fingerprintMetadataBytes +=
      Buffer.byteLength(task.version, 'utf8') +
      Buffer.byteLength(task.inputFingerprint ?? '', 'utf8');
    if (fingerprintMetadataBytes > MAX_ANALYSIS_TASK_METADATA_BYTES)
      throw new RangeError(
        `analysis task fingerprints exceed ${MAX_ANALYSIS_TASK_METADATA_BYTES} bytes`
      );
  }
  const outputDigests = new Map<string, string>();
  const wrapped = tasks.map((task) => ({
    ...task,
    run: async (signal: AbortSignal): Promise<T> => {
      const dependencies = [...new Set(task.dependsOn ?? [])].sort();
      const dependencyDigests = dependencies.map(
        (id) => [id, outputDigests.get(id)] as const
      );
      const hasStableDependencyDigests = dependencyDigests.every(
        (entry) => entry[1] !== undefined
      );
      // The scope already separates cache namespaces; keep the legacy
      // no-fingerprint mode cheap while requiring explicit fingerprints for
      // per-task selective invalidation.
      const inputFingerprint = task.inputFingerprint ?? 'scope-input';
      const version = createHash('sha256')
        .update(
          JSON.stringify({
            version: task.version,
            inputFingerprint,
            dependencyDigests: hasStableDependencyDigests
              ? dependencyDigests
              : undefined
          })
        )
        .digest('hex');
      const canCache = hasStableDependencyDigests && !signal.aborted;
      if (canCache) {
        const cached = options.cache.read<T>(cacheScope, task.id, version);
        if (cached.found) {
          outputDigests.set(task.id, cached.digest);
          return cached.value;
        }
      }
      const value = await task.run(signal);
      if (!signal.aborted && hasStableDependencyDigests) {
        const digest = options.cache.setWithDigest(
          cacheScope,
          task.id,
          version,
          value
        );
        if (digest) outputDigests.set(task.id, digest);
      }
      return value;
    }
  }));
  return runTaskDag(wrapped, options);
}
