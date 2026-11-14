import { setTimeout as delay } from 'node:timers/promises';
import { ToolipError } from '../errors/toolip-error.js';

const MAX_SCAN_DURATION_MS = 600_000;
const MAX_PROVIDER_CONCURRENCY = 32;
const MAX_PROVIDER_RETRIES = 5;
const MAX_RETRY_DELAY_MS = 60_000;

/**
 * Shared execution budget for one scan (issue #48): an absolute deadline, an
 * AbortSignal that fires at the deadline or on external cancellation, a cap on
 * concurrent provider requests and a per-request timeout. Provider code takes a
 * budget instead of inventing its own timers so nothing outlives the scan.
 */
export type ScanBudget = {
  signal: AbortSignal;
  /** `Date.now()`-based absolute deadline. */
  deadlineAt: number;
  maxConcurrentRequests: number;
  requestTimeoutMs: number;
};

export type ScanBudgetOptions = {
  /** Total wall-clock for the whole scan. Default 120 s. */
  totalMs?: number;
  /** Per provider request. Default 15 s. */
  requestTimeoutMs?: number;
  /** Default 8. */
  maxConcurrentRequests?: number;
  /** External cancellation (e.g. CLI interrupt). */
  signal?: AbortSignal;
};

export type ProviderFailureKind =
  'timed_out' | 'cancelled' | 'unavailable' | 'failed';

/** A provider call that did not produce a trustworthy answer. Never "clean". */
export class ProviderError extends ToolipError {
  constructor(
    public readonly kind: ProviderFailureKind,
    message: string,
    public readonly cause?: unknown
  ) {
    super(message, { code: `PROVIDER_${kind.toUpperCase()}`, exitCode: 1 });
    this.name = 'ProviderError';
  }
}

export function createScanBudget(options: ScanBudgetOptions = {}): {
  budget: ScanBudget;
  dispose: () => void;
} {
  const totalMs = options.totalMs ?? 120_000;
  if (
    !Number.isSafeInteger(totalMs) ||
    totalMs < 1 ||
    totalMs > MAX_SCAN_DURATION_MS
  )
    throw new RangeError(
      `scan duration must be an integer from 1 to ${MAX_SCAN_DURATION_MS} milliseconds`
    );
  const maxConcurrentRequests = options.maxConcurrentRequests ?? 8;
  if (
    !Number.isSafeInteger(maxConcurrentRequests) ||
    maxConcurrentRequests < 1 ||
    maxConcurrentRequests > MAX_PROVIDER_CONCURRENCY
  )
    throw new RangeError(
      `provider concurrency must be an integer from 1 to ${MAX_PROVIDER_CONCURRENCY}`
    );
  const requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
  if (
    !Number.isSafeInteger(requestTimeoutMs) ||
    requestTimeoutMs < 1 ||
    requestTimeoutMs > MAX_SCAN_DURATION_MS
  )
    throw new RangeError(
      `provider request timeout must be an integer from 1 to ${MAX_SCAN_DURATION_MS} milliseconds`
    );
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new DeadlineError()),
    totalMs
  );
  timer.unref?.();

  const forward = () => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) forward();
  else options.signal?.addEventListener('abort', forward, { once: true });

  return {
    budget: {
      signal: controller.signal,
      deadlineAt: Date.now() + totalMs,
      maxConcurrentRequests,
      requestTimeoutMs
    },
    dispose: () => {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', forward);
    }
  };
}

class DeadlineError extends Error {
  constructor() {
    super('Scan deadline exceeded.');
    this.name = 'DeadlineError';
  }
}

export type RetryPolicy = {
  /** Retries after the first attempt. Default 2 (3 attempts total). */
  retries?: number;
  baseMs?: number;
  maxMs?: number;
  /** Injectable for deterministic tests. */
  random?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
};

const TRANSIENT_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const TRANSIENT_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'ENOTFOUND',
  'EPIPE',
  'FETCH_ERROR'
]);

/**
 * Runs one provider operation under the budget: each attempt gets a signal
 * that fires at the per-request timeout, the scan deadline or cancellation;
 * transient failures (HTTP 408/425/429/5xx, network resets) retry with capped
 * exponential backoff plus jitter, honoring Retry-After; retries never run
 * past the deadline and never repeat indefinitely. Everything else fails
 * immediately. Complexity: O(attempts), attempts <= retries + 1.
 */
export async function withBudget<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  budget: ScanBudget,
  policy: RetryPolicy = {}
): Promise<T> {
  if (
    !budget?.signal ||
    typeof budget.signal.aborted !== 'boolean' ||
    !Number.isSafeInteger(budget.deadlineAt) ||
    !Number.isSafeInteger(budget.maxConcurrentRequests) ||
    budget.maxConcurrentRequests < 1 ||
    budget.maxConcurrentRequests > MAX_PROVIDER_CONCURRENCY ||
    !Number.isSafeInteger(budget.requestTimeoutMs) ||
    budget.requestTimeoutMs < 1 ||
    budget.requestTimeoutMs > MAX_SCAN_DURATION_MS
  )
    throw new TypeError('provider scan budget is invalid');
  const retries = policy.retries ?? 2;
  if (
    !Number.isSafeInteger(retries) ||
    retries < 0 ||
    retries > MAX_PROVIDER_RETRIES
  )
    throw new RangeError(
      `provider retries must be an integer from 0 to ${MAX_PROVIDER_RETRIES}`
    );
  const baseMs = policy.baseMs ?? 250;
  const maxMs = policy.maxMs ?? 5_000;
  if (
    !Number.isSafeInteger(baseMs) ||
    baseMs < 0 ||
    baseMs > MAX_RETRY_DELAY_MS ||
    !Number.isSafeInteger(maxMs) ||
    maxMs < 0 ||
    maxMs > MAX_RETRY_DELAY_MS
  )
    throw new RangeError(
      `provider retry delays must be integers from 0 to ${MAX_RETRY_DELAY_MS} milliseconds`
    );
  const random = policy.random ?? Math.random;
  const sleep =
    policy.sleep ??
    ((ms: number, signal: AbortSignal) =>
      delay(ms, undefined, { signal }).then(() => undefined));
  if (typeof random !== 'function' || typeof sleep !== 'function')
    throw new TypeError('provider retry functions are invalid');

  for (let attempt = 0; ; attempt += 1) {
    if (budget.signal.aborted) throw abortedError(budget);

    const attemptSignal = AbortSignal.any([
      budget.signal,
      AbortSignal.timeout(budget.requestTimeoutMs)
    ]);

    try {
      return await abortable(operation(attemptSignal), attemptSignal, budget);
    } catch (error) {
      if (error instanceof ProviderError && error.kind !== 'unavailable')
        throw error;
      if (budget.signal.aborted) throw abortedError(budget);

      const failure = classify(error);
      const retryAfterMs = retryAfter(error);
      const randomValue = random();
      if (!Number.isFinite(randomValue) || randomValue < 0 || randomValue > 1)
        throw new RangeError('provider retry random value must be from 0 to 1');
      const delayMs = Math.min(
        maxMs,
        retryAfterMs ?? baseMs * 2 ** attempt * (0.5 + randomValue / 2)
      );
      const remaining = budget.deadlineAt - Date.now();

      if (attempt >= retries || !failure.transient || delayMs >= remaining) {
        throw new ProviderError(
          failure.kind,
          `${failure.message}${attempt > 0 ? ` (after ${attempt + 1} attempts)` : ''}`,
          error
        );
      }

      try {
        await sleep(delayMs, budget.signal);
      } catch {
        throw abortedError(budget);
      }
    }
  }
}

function abortedError(budget: ScanBudget): ProviderError {
  return budget.signal.reason instanceof DeadlineError ||
    Date.now() >= budget.deadlineAt
    ? new ProviderError(
        'timed_out',
        'Scan deadline exceeded before the provider answered.'
      )
    : new ProviderError('cancelled', 'Scan was cancelled.');
}

/** Rejects as soon as the signal aborts, even if the library ignores it. */
function abortable<T>(
  promise: Promise<T>,
  signal: AbortSignal,
  budget: ScanBudget
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(
        budget.signal.aborted
          ? abortedError(budget)
          : new ProviderError('timed_out', 'Provider request timed out.')
      );
    };
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      }
    );
  });
}

function classify(error: unknown): {
  transient: boolean;
  kind: ProviderFailureKind;
  message: string;
} {
  if (error instanceof ProviderError) {
    return {
      transient: error.kind === 'timed_out',
      kind: error.kind,
      message: error.message
    };
  }
  const e = error as {
    statusCode?: number;
    status?: number;
    code?: string;
    message?: string;
  };
  const status = e?.statusCode ?? e?.status;
  const message = e?.message ?? 'Provider request failed.';

  if (typeof status === 'number') {
    return {
      transient: TRANSIENT_STATUS.has(status),
      kind: TRANSIENT_STATUS.has(status) ? 'unavailable' : 'failed',
      message: `Provider responded with HTTP ${status}.`
    };
  }
  if (typeof e?.code === 'string' && TRANSIENT_CODES.has(e.code)) {
    return {
      transient: true,
      kind: 'unavailable',
      message: `Provider unreachable (${e.code}).`
    };
  }
  return { transient: false, kind: 'failed', message };
}

function retryAfter(error: unknown): number | undefined {
  const headers = (error as { headers?: unknown })?.headers as
    | { get?: (name: string) => string | null }
    | Record<string, string | string[] | undefined>
    | undefined;
  const raw =
    typeof (headers as { get?: unknown })?.get === 'function'
      ? (headers as { get: (name: string) => string | null }).get('retry-after')
      : (
          headers as Record<string, string | string[] | undefined> | undefined
        )?.['retry-after'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, date - Date.now());
}
