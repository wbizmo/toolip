export type DepsDevVersionResponse = {
  versionKey?: {
    system?: string;
    name?: string;
    version?: string;
  };
  publishedAt?: string;
  isDefault?: boolean;
  isDeprecated?: boolean;
  deprecatedReason?: string;
  licenses?: string[];
  advisoryKeys?: Array<{
    id?: string;
  }>;
  links?: Array<{
    label?: string;
    url?: string;
  }>;
  slsaProvenances?: Array<{
    sourceRepository?: string;
    commit?: string;
    url?: string;
    verified?: boolean;
  }>;
  attestations?: Array<{
    type?: string;
    url?: string;
    verified?: boolean;
    sourceRepository?: string;
    commit?: string;
  }>;
  registries?: string[];
  relatedProjects?: Array<{
    projectKey?: {
      id?: string;
    };
    relationType?: string;
    relationProvenance?: string;
  }>;
};

/**
 * deps.dev trust annotations are provider assertions. Toolip does not download
 * the referenced attestation or independently verify its signature here.
 */
export function summarizeDepsDevTrust(metadata?: DepsDevVersionResponse) {
  const provenance = metadata?.slsaProvenances ?? [];
  const attestations = metadata?.attestations ?? [];
  return Object.freeze({
    provider: 'deps.dev' as const,
    independentCryptographicVerification: 'not-performed' as const,
    provenance: Object.freeze({
      status: provenance.length === 0 ? ('not-reported' as const) : ('provider-reported' as const),
      records: provenance.length,
      recordsMarkedVerifiedByProvider: provenance.filter(
        (item) => item.verified === true
      ).length
    }),
    attestations: Object.freeze({
      status: attestations.length === 0 ? ('not-reported' as const) : ('provider-reported' as const),
      records: attestations.length,
      recordsMarkedVerifiedByProvider: attestations.filter(
        (item) => item.verified === true
      ).length
    })
  });
}

export type DepsDevDependenciesResponse = {
  nodes?: Array<{
    versionKey?: {
      system?: string;
      name?: string;
      version?: string;
    };
    relation?: string;
    errors?: string[];
  }>;
  edges?: Array<{
    fromNode?: number;
    toNode?: number;
    requirement?: string;
  }>;
  error?: string;
};

export type DepsDevClientOptions = {
  endpoint?: string;
  timeoutMs?: number;
  /** Maximum wall-clock time for one lookup, including retries and backoff. */
  overallBudgetMs?: number;
  fetchImplementation?: typeof fetch;
  maxRetries?: number;
  retryDelayMs?: number;
  /** Successful metadata cache lifetime; set to zero to disable. */
  cacheTtlMs?: number;
  /** Maximum successful metadata entries retained by this client. */
  cacheMaxEntries?: number;
  /** Injectable clock for deterministic cache tests. */
  now?: () => number;
};

export type DepsDevRequestMetrics = Readonly<{
  httpRequests: number;
  peakConcurrency: number;
  throttledResponses: number;
  retries: number;
  cacheHits: number;
}>;

const MAX_RESPONSE_BYTES = 1_048_576;
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_CACHE_MAX_ENTRIES = 2_000;

async function readJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('deps.dev returned an empty response.');
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('deps.dev response exceeded the size limit.');
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(
        Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), bytes)
      )
    ) as unknown;
  } catch {
    throw new Error('deps.dev returned invalid JSON.');
  }
}

type PendingRequest = {
  controller: AbortController;
  waiters: number;
  promise: Promise<unknown>;
};

type CachedResponse = { expiresAt: number; value: unknown };

export class DepsDevClient {
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly overallBudgetMs: number;
  private readonly fetchImplementation: typeof fetch;
  private readonly maxRetries: number;
  private readonly retryDelayMs: number;
  private readonly cacheTtlMs: number;
  private readonly cacheMaxEntries: number;
  private readonly now: () => number;
  private requests = 0;
  private activeRequests = 0;
  private peakConcurrency = 0;
  private throttledResponses = 0;
  private retries = 0;
  private cacheHits = 0;
  private readonly inFlight = new Map<string, PendingRequest>();
  private readonly cache = new Map<string, CachedResponse>();

  constructor(options: DepsDevClientOptions = {}) {
    this.endpoint = options.endpoint ?? 'https://api.deps.dev/v3';
    this.timeoutMs = options.timeoutMs ?? 20_000;
    if (
      !Number.isSafeInteger(this.timeoutMs) ||
      this.timeoutMs < 1 ||
      this.timeoutMs > 60_000
    )
      throw new RangeError('deps.dev timeout must be between 1 and 60000 ms.');
    this.overallBudgetMs = options.overallBudgetMs ?? 60_000;
    if (
      !Number.isSafeInteger(this.overallBudgetMs) ||
      this.overallBudgetMs < 1 ||
      this.overallBudgetMs > 120_000
    )
      throw new RangeError(
        'deps.dev overall budget must be between 1 and 120000 ms.'
      );
    this.fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
    this.maxRetries = options.maxRetries ?? 2;
    if (!Number.isSafeInteger(this.maxRetries) || this.maxRetries < 0 || this.maxRetries > 5)
      throw new RangeError('deps.dev retries must be between 0 and 5.');
    this.retryDelayMs = options.retryDelayMs ?? 200;
    if (!Number.isSafeInteger(this.retryDelayMs) || this.retryDelayMs < 0 || this.retryDelayMs > 5_000)
      throw new RangeError('deps.dev retry delay must be between 0 and 5000 ms.');
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    if (
      !Number.isSafeInteger(this.cacheTtlMs) ||
      this.cacheTtlMs < 0 ||
      this.cacheTtlMs > 24 * 60 * 60 * 1000
    )
      throw new RangeError('deps.dev cache TTL must be between 0 and 86400000 ms.');
    this.cacheMaxEntries = options.cacheMaxEntries ?? DEFAULT_CACHE_MAX_ENTRIES;
    if (
      !Number.isSafeInteger(this.cacheMaxEntries) ||
      this.cacheMaxEntries < 1 ||
      this.cacheMaxEntries > 100_000
    )
      throw new RangeError('deps.dev cache size must be between 1 and 100000 entries.');
    this.now = options.now ?? Date.now;
  }

  async getVersion(
    packageName: string,
    version: string,
    signal?: AbortSignal
  ): Promise<DepsDevVersionResponse> {
    const pathname = `/systems/npm/packages/${encodeURIComponent(
      packageName
    )}/versions/${encodeURIComponent(version)}`;
    return this.coalesce(`version\0${packageName}\0${version}`, signal, (sharedSignal) =>
      this.getJson<DepsDevVersionResponse>(pathname, sharedSignal)
    );
  }

  async getDependencies(
    packageName: string,
    version: string,
    signal?: AbortSignal
  ): Promise<DepsDevDependenciesResponse> {
    const pathname = `/systems/npm/packages/${encodeURIComponent(
      packageName
    )}/versions/${encodeURIComponent(version)}:dependencies`;
    return this.coalesce(`dependencies\0${packageName}\0${version}`, signal, (sharedSignal) =>
      this.getJson<DepsDevDependenciesResponse>(pathname, sharedSignal)
    );
  }

  getMetrics(): DepsDevRequestMetrics {
    return Object.freeze({
      httpRequests: this.requests,
      peakConcurrency: this.peakConcurrency,
      throttledResponses: this.throttledResponses,
      retries: this.retries,
      cacheHits: this.cacheHits
    });
  }

  private coalesce<T>(
    key: string,
    signal: AbortSignal | undefined,
    operation: (signal: AbortSignal) => Promise<T>
  ): Promise<T> {
    if (signal?.aborted)
      return Promise.reject(new Error('deps.dev request cancelled.'));
    const cached = this.cache.get(key);
    if (cached) {
      if (cached.expiresAt > this.now()) {
        this.cacheHits++;
        this.cache.delete(key);
        this.cache.set(key, cached);
        return Promise.resolve(structuredClone(cached.value) as T);
      }
      this.cache.delete(key);
    }
    let pending = this.inFlight.get(key);
    if (!pending) {
      const controller = new AbortController();
      const promise = Promise.resolve().then(() => operation(controller.signal));
      const created: PendingRequest = {
        controller,
        waiters: 0,
        promise: promise.then((value) => {
          if (this.cacheTtlMs > 0) {
            if (this.cache.size >= this.cacheMaxEntries) {
              const oldest = this.cache.keys().next().value as string | undefined;
              if (oldest !== undefined) this.cache.delete(oldest);
            }
            this.cache.set(key, {
              expiresAt: this.now() + this.cacheTtlMs,
              value: structuredClone(value)
            });
          }
          return value;
        })
      };
      pending = created;
      this.inFlight.set(key, created);
      void created.promise.then(
        () => {
          if (this.inFlight.get(key) === created) this.inFlight.delete(key);
        },
        () => {
          if (this.inFlight.get(key) === created) this.inFlight.delete(key);
        }
      );
    }
    const request = pending;
    request.waiters++;
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const finish = (): void => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener('abort', abort);
        request.waiters--;
        if (request.waiters === 0 && this.inFlight.get(key) === request)
          request.controller.abort();
      };
      const abort = (): void => {
        finish();
        reject(new Error('deps.dev request cancelled.'));
      };
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) {
        abort();
        return;
      }
      request.promise.then(
        (value) => {
          if (settled) return;
          finish();
          resolve(value as T);
        },
        (error: unknown) => {
          if (settled) return;
          finish();
          reject(error);
        }
      );
    });
  }

  private async getJson<T>(
    pathname: string,
    outerSignal?: AbortSignal
  ): Promise<T> {
    const deadline = Date.now() + this.overallBudgetMs;
    for (let attempt = 0; ; attempt++) {
      if (outerSignal?.aborted) throw new Error('deps.dev request cancelled.');
      const remainingBudgetMs = deadline - Date.now();
      if (remainingBudgetMs <= 0)
        throw new Error('deps.dev request exceeded its overall budget.');
      const controller = new AbortController();
      let rejectStopped: ((reason: Error) => void) | undefined;
      const stopped = new Promise<never>((_resolve, reject) => {
        rejectStopped = reject;
      });
      let timedOut = false;
      let budgetExpired = false;
      const attemptTimeoutMs = Math.min(this.timeoutMs, remainingBudgetMs);
      const timeout = setTimeout(() => {
        timedOut = true;
        budgetExpired = remainingBudgetMs <= this.timeoutMs;
        controller.abort();
        rejectStopped?.(
          new Error(
            budgetExpired
              ? 'deps.dev request exceeded its overall budget.'
              : 'deps.dev request timed out.'
          )
        );
      }, attemptTimeoutMs);
      const abort = (): void => {
        controller.abort();
        rejectStopped?.(new Error('deps.dev request cancelled.'));
      };
      outerSignal?.addEventListener('abort', abort, { once: true });
      if (outerSignal?.aborted) abort();

      let retryDelay: number | undefined;
      this.requests++;
      this.activeRequests++;
      this.peakConcurrency = Math.max(
        this.peakConcurrency,
        this.activeRequests
      );
      let released = false;
      const release = (): void => {
        if (released) return;
        released = true;
        this.activeRequests--;
      };
      const request = (async (): Promise<{ value: T } | { retry: true }> => {
        const response = await this.fetchImplementation(
          `${this.endpoint}${pathname}`,
          {
            headers: {
              accept: 'application/json',
              'user-agent': 'toolip'
            },
            signal: controller.signal,
            redirect: 'error'
          }
        );

        if (!response.ok) {
          if (response.status === 429) this.throttledResponses++;
          const retryable =
            response.status === 429 ||
            response.status === 500 ||
            response.status === 502 ||
            response.status === 503 ||
            response.status === 504;
          if (retryable && attempt < this.maxRetries) {
            this.retries++;
            retryDelay = this.retryAfterMs(response.headers.get('retry-after'));
            await response.body?.cancel().catch(() => undefined);
            return { retry: true };
          }
          await response.body?.cancel().catch(() => undefined);
          throw new Error(
            `deps.dev request failed with HTTP ${response.status}.`
          );
        }
        return { value: (await readJson(response)) as T };
      })();
      const trackedRequest = request.then(
        (value) => {
          release();
          return value;
        },
        (error: unknown) => {
          release();
          throw error;
        }
      );
      try {
        const result = await Promise.race([trackedRequest, stopped]);
        if ('value' in result) return result.value;
      } catch (error) {
        if (outerSignal?.aborted)
          throw new Error('deps.dev request cancelled.');
        if (budgetExpired) throw new Error('deps.dev request exceeded its overall budget.');
        if (timedOut || controller.signal.aborted)
          throw new Error('deps.dev request timed out.');
        throw error;
      } finally {
        clearTimeout(timeout);
        outerSignal?.removeEventListener('abort', abort);
        // A provider that ignores abort remains active in the accounting pool
        // until its underlying promise settles, even though the caller timed
        // out. This prevents resource budgets from being bypassed by zombies.
        if (released) release();
      }

      const exponential = Math.min(5_000, this.retryDelayMs * 2 ** attempt);
      const jittered = Math.floor(exponential * (0.5 + Math.random()));
      const backoffMs = Math.max(jittered, retryDelay ?? 0);
      if (backoffMs >= deadline - Date.now())
        throw new Error('deps.dev request exceeded its overall budget.');
      await delay(backoffMs, outerSignal);
    }
  }

  private retryAfterMs(value: string | null): number | undefined {
    if (!value) return undefined;
    const seconds = Number(value);
    const parsed = Number.isFinite(seconds)
      ? seconds * 1_000
      : Date.parse(value) - Date.now();
    if (!Number.isFinite(parsed) || parsed < 0) return undefined;
    return Math.min(10_000, parsed);
  }
}

/** Process-local bounded TTL cache for default, public deps.dev metadata calls. */
export const sharedDepsDevClient = new DepsDevClient();

async function delay(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) throw new Error('deps.dev request cancelled.');
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener('abort', abort);
      resolve();
    }, ms);
    const abort = () => {
      clearTimeout(timeout);
      reject(new Error('deps.dev request cancelled.'));
    };
    signal?.addEventListener('abort', abort, { once: true });
  });
}
