import { describe, expect, it, vi } from 'vitest';
import {
  DepsDevClient,
  summarizeDepsDevTrust
} from '../../src/providers/depsdev/client.js';

describe('DepsDevClient', () => {
  it('keeps provider trust annotations distinct from independent verification', () => {
    expect(
      summarizeDepsDevTrust({
        slsaProvenances: [{ verified: true }, { verified: false }],
        attestations: [{ verified: true }]
      })
    ).toEqual({
      provider: 'deps.dev',
      independentCryptographicVerification: 'not-performed',
      provenance: {
        status: 'provider-reported',
        records: 2,
        recordsMarkedVerifiedByProvider: 1
      },
      attestations: {
        status: 'provider-reported',
        records: 1,
        recordsMarkedVerifiedByProvider: 1
      }
    });
    expect(summarizeDepsDevTrust()).toMatchObject({
      provenance: { status: 'not-reported', records: 0 },
      attestations: { status: 'not-reported', records: 0 },
      independentCryptographicVerification: 'not-performed'
    });
  });

  it('encodes npm package names and versions', async () => {
    const fetchImplementation = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            licenses: ['MIT']
          }),
          {
            status: 200
          }
        )
    ) as unknown as typeof fetch;

    const client = new DepsDevClient({
      fetchImplementation
    });

    const result = await client.getVersion('@scope/package', '1.0.0');

    expect(result.licenses).toEqual(['MIT']);
    expect(fetchImplementation).toHaveBeenCalledWith(
      expect.stringContaining('%40scope%2Fpackage/versions/1.0.0'),
      expect.any(Object)
    );
  });

  it('retries throttling with a bounded retry-after delay', async () => {
    let calls = 0;
    const fetchImplementation = vi.fn(async () => {
      calls++;
      if (calls === 1) {
        return new Response('busy', {
          status: 429,
          headers: { 'retry-after': '0' }
        });
      }
      return new Response(JSON.stringify({ licenses: ['MIT'] }), {
        status: 200
      });
    }) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      retryDelayMs: 0,
      maxRetries: 2
    });

    await expect(client.getVersion('safe', '1.0.0')).resolves.toMatchObject({
      licenses: ['MIT']
    });
    expect(calls).toBe(2);
    expect(client.getMetrics()).toMatchObject({
      httpRequests: 2,
      throttledResponses: 1,
      retries: 1,
      peakConcurrency: 1
    });
  });

  it('does not retry permanent client errors', async () => {
    const fetchImplementation = vi.fn(
      async () => new Response('missing', { status: 404 })
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({ fetchImplementation, retryDelayMs: 0 });

    await expect(client.getVersion('missing', '1.0.0')).rejects.toThrow(
      'HTTP 404'
    );
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
    expect(client.getMetrics()).toMatchObject({
      httpRequests: 1,
      throttledResponses: 0,
      retries: 0
    });
  });

  it('stops after bounded retries are exhausted', async () => {
    const fetchImplementation = vi.fn(
      async () =>
        new Response('busy', {
          status: 429,
          headers: { 'retry-after': '0' }
        })
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      retryDelayMs: 0,
      maxRetries: 1
    });

    await expect(client.getVersion('busy', '1.0.0')).rejects.toThrow(
      'HTTP 429'
    );
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect(client.getMetrics()).toMatchObject({
      httpRequests: 2,
      throttledResponses: 2,
      retries: 1
    });
  });

  it('returns on timeout even if a provider ignores AbortSignal', async () => {
    let requestSignal: AbortSignal | undefined;
    const fetchImplementation = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        requestSignal = init?.signal ?? undefined;
        return await new Promise<Response>(() => undefined);
      }
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      timeoutMs: 5,
      maxRetries: 0
    });

    await expect(client.getVersion('safe', '1.0.0')).rejects.toThrow(
      'timed out'
    );
    expect(requestSignal?.aborted).toBe(true);
    expect(client.getMetrics().peakConcurrency).toBe(1);
  });

  it('applies one overall budget across a lookup and its retries', async () => {
    let requestSignal: AbortSignal | undefined;
    const fetchImplementation = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        requestSignal = init?.signal ?? undefined;
        return await new Promise<Response>(() => undefined);
      }
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      timeoutMs: 1_000,
      overallBudgetMs: 5,
      maxRetries: 2
    });

    await expect(client.getVersion('bounded', '1.0.0')).rejects.toThrow(
      'overall budget'
    );
    expect(requestSignal?.aborted).toBe(true);
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
    expect(() => new DepsDevClient({ overallBudgetMs: 0 })).toThrow(
      'overall budget must be between'
    );
  });

  it('propagates external cancellation to the provider and settles the caller', async () => {
    let requestSignal: AbortSignal | undefined;
    const fetchImplementation = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        requestSignal = init?.signal ?? undefined;
        return await new Promise<Response>(() => undefined);
      }
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      timeoutMs: 5_000,
      maxRetries: 0
    });
    const controller = new AbortController();
    const pending = client.getVersion('safe', '1.0.0', controller.signal);
    await new Promise((resolve) => setTimeout(resolve, 0));
    controller.abort();

    await expect(pending).rejects.toThrow('cancelled');
    expect(requestSignal?.aborted).toBe(true);
  });

  it('coalesces concurrent identical package requests without coupling caller cancellation', async () => {
    let resolveResponse!: (response: Response) => void;
    let requestSignal: AbortSignal | undefined;
    const fetchImplementation = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) => {
        requestSignal = init?.signal ?? undefined;
        return await new Promise<Response>((resolve) => {
          resolveResponse = resolve;
        });
      }
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      maxRetries: 0
    });
    const firstAbort = new AbortController();
    const first = client.getVersion('same-package', '1.0.0', firstAbort.signal);
    const second = client.getVersion('same-package', '1.0.0');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fetchImplementation).toHaveBeenCalledTimes(1);

    firstAbort.abort();
    await expect(first).rejects.toThrow('cancelled');
    expect(requestSignal?.aborted).toBe(false);
    resolveResponse(new Response(JSON.stringify({ licenses: ['MIT'] })));
    await expect(second).resolves.toMatchObject({ licenses: ['MIT'] });
    expect(client.getMetrics().httpRequests).toBe(1);
  });

  it('caches only successful responses with bounded TTL and cloned values', async () => {
    let now = 1_000;
    const fetchImplementation = vi.fn(async () =>
      new Response(JSON.stringify({ licenses: ['MIT'] }), { status: 200 })
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      cacheTtlMs: 100,
      cacheMaxEntries: 1,
      now: () => now,
      maxRetries: 0
    });

    const first = await client.getVersion('cached', '1.0.0');
    first.licenses?.push('MUTATED');
    await expect(client.getVersion('cached', '1.0.0')).resolves.toMatchObject({
      licenses: ['MIT']
    });
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
    expect(client.getMetrics().cacheHits).toBe(1);

    await client.getVersion('evictor', '1.0.0');
    await client.getVersion('cached', '1.0.0');
    expect(fetchImplementation).toHaveBeenCalledTimes(3);

    now += 101;
    await client.getVersion('cached', '1.0.0');
    expect(fetchImplementation).toHaveBeenCalledTimes(4);
  });

  it('does not cache failed lookups or responses when TTL caching is disabled', async () => {
    const fetchImplementation = vi.fn(
      async () => new Response(JSON.stringify({ licenses: ['MIT'] }))
    ) as unknown as typeof fetch;
    const client = new DepsDevClient({
      fetchImplementation,
      cacheTtlMs: 0,
      maxRetries: 0
    });
    await client.getVersion('uncached', '1.0.0');
    await client.getVersion('uncached', '1.0.0');
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    const failedFetch = vi.fn(
      async () => new Response('missing', { status: 404 })
    ) as unknown as typeof fetch;
    const failingClient = new DepsDevClient({
      fetchImplementation: failedFetch,
      maxRetries: 0
    });
    await expect(failingClient.getVersion('missing', '1.0.0')).rejects.toThrow(
      'HTTP 404'
    );
    await expect(failingClient.getVersion('missing', '1.0.0')).rejects.toThrow(
      'HTTP 404'
    );
    expect(failedFetch).toHaveBeenCalledTimes(2);
  });

  it('rejects oversized provider responses and invalid budget configuration', async () => {
    const client = new DepsDevClient({
      fetchImplementation: async () =>
        new Response(JSON.stringify({ value: 'x'.repeat(1_050_000) })),
      maxRetries: 0
    });
    await expect(client.getVersion('large', '1.0.0')).rejects.toThrow(
      'size limit'
    );
    expect(() => new DepsDevClient({ timeoutMs: 0 })).toThrow(
      'timeout must be between'
    );
    expect(() => new DepsDevClient({ maxRetries: 6 })).toThrow(
      'retries must be between'
    );
    expect(() => new DepsDevClient({ cacheTtlMs: -1 })).toThrow(
      'cache TTL must be between'
    );
    expect(() => new DepsDevClient({ cacheMaxEntries: 0 })).toThrow(
      'cache size must be between'
    );
  });
});
