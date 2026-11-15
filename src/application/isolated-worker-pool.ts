/**
 * Process-wide bound for isolated analyzer workers. AnalyzerRunner instances
 * are created per scan, so a per-instance concurrency limit alone permits
 * concurrent scans to multiply their worker heaps without a shared ceiling.
 */
export const MAX_CONCURRENT_ISOLATED_ANALYZER_WORKERS = 2;
/** Aggregate V8 old-generation ceilings across active isolated workers. */
export const MAX_ACTIVE_ISOLATED_ANALYZER_OLD_GENERATION_MB = 1_024;
/** Maximum estimated structured-clone input retained by running workers. */
export const MAX_ACTIVE_ISOLATED_ANALYZER_CONTEXT_BYTES = 640 * 1024 * 1024;
/** Maximum estimated input retained by queued worker requests. */
export const MAX_QUEUED_ISOLATED_ANALYZER_CONTEXT_BYTES = 512 * 1024 * 1024;
/** Per request ceiling includes snapshot metadata and structured-clone overhead. */
export const MAX_ISOLATED_ANALYZER_CONTEXT_BYTES = 320 * 1024 * 1024;
const MAX_QUEUED_ISOLATED_ANALYZER_WORKERS = 256;

type Waiter = {
  resolve: (release: () => void) => void;
  reject: (error: Error) => void;
  signal?: AbortSignal;
  abort?: () => void;
  timeout?: ReturnType<typeof setTimeout>;
  contextBytes: number;
  oldGenerationMb: number;
  previous?: Waiter;
  next?: Waiter;
  queued: boolean;
};

let activeWorkers = 0;
let queueHead: Waiter | undefined;
let queueTail: Waiter | undefined;
let queueLength = 0;
let activeContextBytes = 0;
let queuedContextBytes = 0;
let activeOldGenerationMb = 0;

function enqueue(waiter: Waiter): void {
  waiter.previous = queueTail;
  if (queueTail) queueTail.next = waiter;
  else queueHead = waiter;
  queueTail = waiter;
  waiter.queued = true;
  queueLength += 1;
}

function remove(waiter: Waiter): boolean {
  if (!waiter.queued) return false;
  if (waiter.previous) waiter.previous.next = waiter.next;
  else queueHead = waiter.next;
  if (waiter.next) waiter.next.previous = waiter.previous;
  else queueTail = waiter.previous;
  waiter.previous = undefined;
  waiter.next = undefined;
  waiter.queued = false;
  queueLength -= 1;
  queuedContextBytes -= waiter.contextBytes;
  return true;
}

/** Acquire a process-wide worker slot, preserving FIFO order and cancellation. */
export function acquireIsolatedAnalyzerWorkerSlot(
  signal: AbortSignal | undefined,
  timeoutMs: number,
  contextBytes: number,
  oldGenerationMb: number
): Promise<() => void> {
  if (signal?.aborted) return Promise.reject(cancellationError(signal));
  if (
    !Number.isSafeInteger(contextBytes) ||
    contextBytes < 0 ||
    contextBytes > MAX_ISOLATED_ANALYZER_CONTEXT_BYTES
  )
    return Promise.reject(
      new Error('isolated analyzer context exceeds its memory budget')
    );
  if (
    !Number.isSafeInteger(oldGenerationMb) ||
    oldGenerationMb < 16 ||
    oldGenerationMb > MAX_ACTIVE_ISOLATED_ANALYZER_OLD_GENERATION_MB
  )
    return Promise.reject(new Error('isolated analyzer heap exceeds its budget'));

  return new Promise((resolve, reject) => {
    const waiter: Waiter = {
      resolve,
      reject,
      signal,
      queued: false,
      contextBytes,
      oldGenerationMb
    };
    if (
      activeWorkers < MAX_CONCURRENT_ISOLATED_ANALYZER_WORKERS &&
      activeOldGenerationMb + oldGenerationMb <=
        MAX_ACTIVE_ISOLATED_ANALYZER_OLD_GENERATION_MB &&
      activeContextBytes + contextBytes <=
        MAX_ACTIVE_ISOLATED_ANALYZER_CONTEXT_BYTES
    ) {
      start(waiter);
      return;
    }
    if (queueLength >= MAX_QUEUED_ISOLATED_ANALYZER_WORKERS) {
      reject(new Error('isolated analyzer worker queue is full'));
      return;
    }
    if (
      queuedContextBytes + contextBytes >
      MAX_QUEUED_ISOLATED_ANALYZER_CONTEXT_BYTES
    ) {
      reject(new Error('isolated analyzer worker queue memory budget is full'));
      return;
    }

    if (signal) {
      waiter.abort = () => {
        remove(waiter);
        reject(cancellationError(signal));
      };
      signal.addEventListener('abort', waiter.abort, { once: true });
    }
    waiter.timeout = setTimeout(() => {
      if (!remove(waiter)) return;
      if (waiter.abort && signal)
        signal.removeEventListener('abort', waiter.abort);
      const error = new Error('isolated analyzer worker queue wait timed out');
      error.name = 'TimeoutError';
      reject(error);
    }, timeoutMs);
    enqueue(waiter);
    queuedContextBytes += contextBytes;
  });
}

function start(waiter: Waiter): void {
  activeWorkers += 1;
  activeContextBytes += waiter.contextBytes;
  activeOldGenerationMb += waiter.oldGenerationMb;
  waiter.resolve(
    releaseFactory(waiter.contextBytes, waiter.oldGenerationMb)
  );
}

function releaseFactory(contextBytes: number, oldGenerationMb: number): () => void {
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeContextBytes -= contextBytes;
    activeOldGenerationMb -= oldGenerationMb;
    activeWorkers -= 1;

    while (queueHead) {
      const next = queueHead;
      if (
        activeWorkers >= MAX_CONCURRENT_ISOLATED_ANALYZER_WORKERS ||
        activeOldGenerationMb + next.oldGenerationMb >
          MAX_ACTIVE_ISOLATED_ANALYZER_OLD_GENERATION_MB ||
        activeContextBytes + next.contextBytes >
          MAX_ACTIVE_ISOLATED_ANALYZER_CONTEXT_BYTES
      )
        return;
      remove(next);
      if (next.timeout) clearTimeout(next.timeout);
      if (next.abort && next.signal) {
        next.signal.removeEventListener('abort', next.abort);
        if (next.signal.aborted) {
          next.reject(cancellationError(next.signal));
          continue;
        }
      }
      start(next);
    }
  };
}

function cancellationError(signal: AbortSignal): Error {
  if (signal.reason instanceof Error) return signal.reason;
  const error = new Error('Operation was cancelled.');
  error.name = 'AbortError';
  return error;
}
