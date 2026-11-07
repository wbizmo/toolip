import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import pacote from 'pacote';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildSecurityScorecard } from '../../src/application/security-scorecard.js';
import { fetchPackageManifest } from '../../src/core/npm-registry.js';
import { scanDependencies } from '../../src/core/dependency-scan.js';
import {
  createScanBudget,
  ProviderError,
  type ScanBudget,
  withBudget
} from '../../src/core/scan-budget.js';

const disposers: Array<() => void> = [];
const servers: http.Server[] = [];
const dirs: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  for (const dispose of disposers.splice(0)) dispose();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
  for (const server of servers.splice(0)) {
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

function budget(
  options: Parameters<typeof createScanBudget>[0] = {}
): ScanBudget {
  const created = createScanBudget(options);
  disposers.push(created.dispose);
  return created.budget;
}

const noSleep = { sleep: async () => undefined, random: () => 0.5 };
const httpError = (statusCode: number, headers?: Record<string, string>) =>
  Object.assign(new Error(`HTTP ${statusCode}`), { statusCode, headers });

// Issue #48: pacote requests ran outside every deadline and could hang a scan forever.
describe('scan budget and bounded retries (issue #48)', () => {
  it('returns a bounded timed_out result for a hanging provider and aborts the request signal', async () => {
    const b = budget({ requestTimeoutMs: 60, totalMs: 5_000 });
    let observed: AbortSignal | undefined;
    const startedAt = performance.now();

    const failure = await withBudget(
      (signal) => {
        observed = signal;
        return new Promise<never>(() => undefined); // never settles, ignores the signal
      },
      b,
      { ...noSleep, retries: 0 }
    ).catch((e) => e);

    expect(failure).toBeInstanceOf(ProviderError);
    expect(failure.kind).toBe('timed_out');
    expect(performance.now() - startedAt).toBeLessThan(1_000);
    expect(observed?.aborted).toBe(true);
  });

  it('retries transient failures with capped attempts and then reports unavailable', async () => {
    const attempts = vi.fn(async () => {
      throw httpError(503);
    });

    const failure = await withBudget(attempts, budget(), {
      ...noSleep,
      retries: 2
    }).catch((e) => e);

    expect(attempts).toHaveBeenCalledTimes(3); // 1 + 2 retries, never more
    expect(failure.kind).toBe('unavailable');
    expect(failure.message).toContain('HTTP 503');
    expect(failure.message).toContain('3 attempts');
  });

  it('recovers when a transient error clears, and does not retry permanent errors', async () => {
    let calls = 0;
    const flaky = vi.fn(async () => {
      calls += 1;
      if (calls < 3) throw httpError(429);
      return 'ok';
    });
    await expect(
      withBudget(flaky, budget(), { ...noSleep, retries: 3 })
    ).resolves.toBe('ok');
    expect(flaky).toHaveBeenCalledTimes(3);

    const notFound = vi.fn(async () => {
      throw httpError(404);
    });
    const failure = await withBudget(notFound, budget(), {
      ...noSleep,
      retries: 3
    }).catch((e) => e);
    expect(notFound).toHaveBeenCalledTimes(1);
    expect(failure.kind).toBe('failed');
  });

  it('honors Retry-After (seconds and HTTP-date) capped by maxMs', async () => {
    const sleeps: number[] = [];
    const sleep = async (ms: number) => {
      sleeps.push(ms);
    };
    let calls = 0;
    const op = async () => {
      calls += 1;
      if (calls === 1) throw httpError(429, { 'retry-after': '2' });
      if (calls === 2)
        throw httpError(503, {
          'retry-after': new Date(Date.now() + 60_000).toUTCString()
        });
      return 'done';
    };

    await withBudget(op, budget(), {
      retries: 3,
      maxMs: 3_000,
      sleep,
      random: () => 0.5
    });

    expect(sleeps[0]).toBe(2_000);
    expect(sleeps[1]).toBe(3_000); // 60 s requested, capped
  });

  it('applies exponential backoff with jitter, bounded by maxMs', async () => {
    const sleeps: number[] = [];
    await withBudget(
      async () => {
        throw httpError(502);
      },
      budget(),
      {
        retries: 3,
        baseMs: 100,
        maxMs: 350,
        random: () => 1,
        sleep: async (ms) => void sleeps.push(ms)
      }
    ).catch(() => undefined);

    expect(sleeps).toEqual([100, 200, 350]); // 100·2^n·(0.5+random/2), capped at 350
  });

  it('never retries past the scan deadline', async () => {
    const b = budget({ totalMs: 40, requestTimeoutMs: 1_000 });
    const attempts = vi.fn(async () => {
      throw httpError(503, { 'retry-after': '30' }); // would sleep 30 s
    });
    const startedAt = performance.now();

    const failure = await withBudget(attempts, b, { retries: 5 }).catch(
      (e) => e
    );

    expect(attempts).toHaveBeenCalledTimes(1);
    expect(failure).toBeInstanceOf(ProviderError);
    expect(performance.now() - startedAt).toBeLessThan(1_000);
  });

  it('reports cancelled (not timed_out) when the caller aborts, and stops retrying', async () => {
    const controller = new AbortController();
    const b = budget({ signal: controller.signal });
    const op = vi.fn(
      (signal: AbortSignal) =>
        new Promise<never>((_, reject) =>
          signal.addEventListener('abort', () => reject(new Error('aborted')))
        )
    );
    setTimeout(() => controller.abort(), 20);

    const failure = await withBudget(op, b).catch((e) => e);

    expect(failure.kind).toBe('cancelled');
    expect(op).toHaveBeenCalledTimes(1);
  });

  it('closes the underlying socket when a request is cancelled', async () => {
    const closed = { value: false };
    const server = http.createServer(() => undefined);
    server.on('connection', (socket) =>
      socket.on('close', () => (closed.value = true))
    );
    servers.push(server);
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;

    const failure = await withBudget(
      (signal) => fetch(`http://127.0.0.1:${port}/`, { signal }),
      budget({ requestTimeoutMs: 80 }),
      { retries: 0 }
    ).catch((e) => e);

    expect(failure.kind).toBe('timed_out');
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(closed.value).toBe(true);
  });

  it('retries a real HTTP 503 and then succeeds', async () => {
    let hits = 0;
    const server = http.createServer((_req, res) => {
      hits += 1;
      res.statusCode = hits < 3 ? 503 : 200;
      res.setHeader('retry-after', '0');
      res.end(hits < 3 ? '' : '{"ok":true}');
    });
    servers.push(server);
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;

    const body = await withBudget(
      async (signal) => {
        const response = await fetch(`http://127.0.0.1:${port}/`, { signal });
        if (!response.ok)
          throw httpError(response.status, {
            'retry-after': response.headers.get('retry-after') ?? ''
          });
        return response.json();
      },
      budget(),
      { retries: 3, baseMs: 1, maxMs: 5 }
    );

    expect(body).toEqual({ ok: true });
    expect(hits).toBe(3);
  });
});

describe('registry manifest fetching under a budget (issue #48)', () => {
  let manifest: ReturnType<typeof vi.spyOn<typeof pacote, 'manifest'>>;

  beforeEach(() => {
    // Default to a loud failure so no test can silently reach the real registry.
    manifest = vi
      .spyOn(pacote, 'manifest')
      .mockRejectedValue(
        new Error('unexpected real registry call in a unit test')
      );
  });

  it('passes the signal, a per-request timeout and zero library retries to pacote', async () => {
    manifest.mockResolvedValueOnce({ name: 'left', version: '1.0.0' });
    const b = budget({ requestTimeoutMs: 1234 });

    await expect(fetchPackageManifest('left', b)).resolves.toMatchObject({
      name: 'left'
    });

    const options = manifest.mock.calls.at(-1)?.[1];
    expect(options).toMatchObject({ timeout: 1234, fetchRetries: 0 });
    expect(options?.signal).toBeInstanceOf(AbortSignal);
  });

  it('a hanging mocked registry yields a bounded timed_out result', async () => {
    manifest.mockImplementation(() => new Promise(() => undefined));
    const startedAt = performance.now();

    const failure = await fetchPackageManifest(
      'hang',
      budget({ requestTimeoutMs: 50 })
    ).catch((e) => e);

    expect(failure).toBeInstanceOf(ProviderError);
    expect(failure.kind).toBe('timed_out');
    expect(performance.now() - startedAt).toBeLessThan(3_000);
  });

  it.each([
    ['empty object', {}],
    ['null', null],
    ['truncated manifest without a version', { name: 'x' }],
    ['non-object', 'oops']
  ])('fails closed on a malformed response (%s)', async (_label, response) => {
    manifest.mockResolvedValueOnce(response as never);
    const failure = await fetchPackageManifest('x', budget()).catch((e) => e);
    expect(failure).toBeInstanceOf(ProviderError);
    expect(failure.kind).toBe('failed');
  });

  it('fails closed (no retry) on malformed JSON from the registry', async () => {
    manifest.mockRejectedValue(new SyntaxError('Unexpected end of JSON input'));
    const failure = await fetchPackageManifest('x', budget()).catch((e) => e);
    expect(failure.kind).toBe('failed');
    expect(manifest).toHaveBeenCalledTimes(1);
  });

  it('retries HTTP 429/503 from the registry a bounded number of times', async () => {
    manifest.mockRejectedValue(httpError(503));
    const failure = await fetchPackageManifest('flaky', budget()).catch(
      (e) => e
    );
    expect(failure.kind).toBe('unavailable');
    expect(failure.message).toContain('attempts');
    // Library retries are disabled, so every attempt here is one of ours; the
    // default policy allows at most 3.
    expect(manifest.mock.calls.length).toBeLessThanOrEqual(3);
    expect(manifest.mock.calls.length).toBeGreaterThan(1);
  });
});

describe('scanDependencies and the scorecard under a budget (issue #48)', () => {
  function project(dependencies: Record<string, string>): string {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-budget-'));
    dirs.push(dir);
    writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ name: 'p', version: '1.0.0', dependencies })
    );
    return dir;
  }

  it('does not query manifest ranges as if they were installed identities', async () => {
    const root = project({ good: '1.0.0', slow: '1.0.0', broken: '1.0.0' });
    const registry = vi.spyOn(pacote, 'manifest');

    const result = await scanDependencies(root, {
      budget: budget({ requestTimeoutMs: 60 })
    });

    expect(result.packages).toEqual([]);
    expect(registry).not.toHaveBeenCalled();
    expect(result.failures.map((f) => [f.name, f.kind]).sort()).toEqual([
      ['broken', 'unresolved'],
      ['good', 'unresolved'],
      ['slow', 'unresolved']
    ]);
    expect(result.coverage).toMatchObject({
      state: 'failed',
      eligible: 3,
      scanned: 0
    });
  });

  it('marks manifest-only packages unresolved without querying the provider', async () => {
    const names = Object.fromEntries(
      Array.from({ length: 12 }, (_, i) => [`pkg-${i}`, '1.0.0'])
    );
    const root = project(names);
    const registry = vi.spyOn(pacote, 'manifest');

    const result = await scanDependencies(root, {
      budget: budget({ maxConcurrentRequests: 3 })
    });

    expect(registry).not.toHaveBeenCalled();
    expect(result.failures).toHaveLength(12);
    expect(result.coverage.state).toBe('failed');
  });

  it('the scorecard returns within its deadline, marks dependency health unmeasured and the run partial', async () => {
    const root = project({ slow: '1.0.0' });
    vi.spyOn(pacote, 'manifest').mockImplementation(
      () => new Promise(() => undefined)
    );
    const startedAt = performance.now();

    const scorecard = await buildSecurityScorecard(
      root,
      {
        // The vulnerability lookup is not under test here.
        vulnerabilityAnalyzer: {
          id: 'osv',
          version: '1',
          analyze: async () => ({
            analyzer: 'osv',
            durationMs: 0,
            findings: []
          })
        }
      },
      { budget: { totalMs: 5_000, requestTimeoutMs: 60 } }
    );

    expect(performance.now() - startedAt).toBeLessThan(4_000);
    expect(scorecard.score.dependencyHealth).toBeNull();
    expect(scorecard.analysis.state).toBe('partial');
    expect(scorecard.analysis.reasons.join(' ')).toContain('dependency health');
    expect(scorecard.warnings.join(' ')).toContain('slow@1.0.0: unresolved');
  });
});
