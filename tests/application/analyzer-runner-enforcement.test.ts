import { once } from 'node:events';
import {
  appendFileSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AnalyzerRunner } from '../../src/application/analyzer-runner.js';
import type { Analyzer } from '../../src/contracts/analyzer.js';
import { AstSecurityAnalyzer } from '../../src/analyzers/ast/ast-security-analyzer.js';
import {
  EchoAnalyzer,
  SpinAnalyzer,
  ThrowingAnalyzer
} from '../fixtures/analyzers/isolated-fixtures.js';

const dirs: string[] = [];
const servers: http.Server[] = [];
afterEach(async () => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
  for (const server of servers.splice(0)) {
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

const tmp = () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-runner-'));
  dirs.push(dir);
  return dir;
};
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const size = (file: string) => statSync(file).size;
/** Worker start-up (module load, tsx) is slow under load; wait for real activity instead of guessing. */
async function waitForSize(file: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (size(file) === 0) {
    if (Date.now() > deadline) throw new Error('side-effect file never grew');
    await sleep(10);
  }
}

function inProcess(id: string, analyze: Analyzer['analyze']): Analyzer {
  return { id, version: '1.0.0', analyze };
}

// Issue #34: a non-cooperative analyzer used to keep running after the runner
// returned and freed its slot.
describe('AnalyzerRunner deadline enforcement (issue #34)', () => {
  it('terminates a synchronous CPU-bound analyzer within the deadline without stalling the parent', async () => {
    const dir = tmp();
    const file = path.join(dir, 'side-effect.txt');
    writeFileSync(file, '');

    // Heartbeat proves the parent event loop kept running while the worker spun.
    let ticks = 0;
    const heartbeat = setInterval(() => {
      ticks += 1;
    }, 10);

    const timeoutMs = 2_500;
    const startedAt = performance.now();
    const running = new AnalyzerRunner({ timeoutMs }).run(
      [new SpinAnalyzer()],
      {
        root: dir,
        options: { sideEffectFile: file }
      }
    );
    await waitForSize(file); // the worker is demonstrably spinning in a synchronous loop
    const [result] = await running;
    const elapsed = performance.now() - startedAt;
    clearInterval(heartbeat);

    expect(result?.status).toBe('timed_out');
    expect(result?.findings).toEqual([]);
    expect(elapsed).toBeLessThan(timeoutMs + 5_000); // terminated, not left spinning
    expect(ticks).toBeGreaterThan(5);

    // After the slot is released the analyzer must be dead: no more writes.
    const after = size(file);
    expect(after).toBeGreaterThan(0);
    await sleep(300);
    expect(size(file)).toBe(after);
  }, 30_000);

  it('does not release the slot until the worker has actually stopped (timeout storm stays bounded)', async () => {
    const dir = tmp();
    const analyzers = Array.from({ length: 9 }, (_, index) => {
      const spin = new SpinAnalyzer();
      return Object.assign(Object.create(spin), {
        id: `spin-${index}`,
        isolation: spin.isolation
      }) as Analyzer;
    });
    const runner = new AnalyzerRunner({ concurrency: 3, timeoutMs: 150 });
    const file = path.join(dir, 'storm.txt');
    writeFileSync(file, '');

    const results = await runner.run(analyzers, {
      root: dir,
      options: { sideEffectFile: file }
    });

    expect(results).toHaveLength(9);
    expect(results.every((result) => result.status === 'timed_out')).toBe(true);
    expect(runner.stats.peakActive).toBeLessThanOrEqual(3);
    expect(runner.stats.active).toBe(0);

    const after = size(file);
    await sleep(300);
    expect(size(file)).toBe(after); // nothing from any timed-out worker keeps writing
  }, 60_000);

  it('keeps sibling results when one analyzer times out or fails', async () => {
    const dir = tmp();
    const file = path.join(dir, 'sibling.txt');
    writeFileSync(file, '');
    const healthy = inProcess('healthy', async () => ({
      analyzer: 'healthy',
      durationMs: 0,
      findings: []
    }));

    const results = await new AnalyzerRunner({
      concurrency: 4,
      timeoutMs: 4_000
    }).run(
      [new SpinAnalyzer(), healthy, new ThrowingAnalyzer(), new EchoAnalyzer()],
      { root: dir, options: { sideEffectFile: file } }
    );

    expect(results.map((r) => r.status)).toEqual([
      'timed_out',
      'ok',
      'failed',
      'ok'
    ]);
    expect(results[2]?.error).toContain('exploded inside the worker');
    expect(results[3]?.metadata).toMatchObject({ answer: 42, root: dir });
  }, 30_000);

  it('flags a non-cooperative in-process analyzer as unresponsive instead of pretending it stopped', async () => {
    let stillRunning = true;
    const stubborn = inProcess('stubborn', async () => {
      await sleep(5_000); // ignores the AbortSignal entirely
      stillRunning = false;
      return { analyzer: 'stubborn', durationMs: 0, findings: [] };
    });

    const [result] = await new AnalyzerRunner({
      timeoutMs: 30,
      graceMs: 50
    }).run([stubborn], { root: process.cwd() });

    expect(result?.status).toBe('timed_out');
    expect(result?.unresponsive).toBe(true);
    expect(result?.warnings?.join(' ')).toContain('declare worker isolation');
    expect(stillRunning).toBe(true);
  });

  it('lets a cooperative analyzer stop within the grace period and holds its slot meanwhile', async () => {
    let stoppedAt: number | undefined;
    const cooperative = inProcess('coop', async (context) => {
      await new Promise<void>((resolve) =>
        context.signal?.addEventListener('abort', () => resolve(), {
          once: true
        })
      );
      stoppedAt = performance.now();
      return { analyzer: 'coop', durationMs: 0, findings: [] };
    });
    const runner = new AnalyzerRunner({ timeoutMs: 30, graceMs: 500 });

    const [result] = await runner.run([cooperative], { root: process.cwd() });

    expect(result?.status).toBe('timed_out');
    expect(result?.unresponsive).toBeUndefined();
    expect(stoppedAt).toBeDefined();
    expect(runner.stats.active).toBe(0);
  });

  it('never starts work once cancellation was requested', async () => {
    let started = false;
    const analyzer = inProcess('never-started', async () => {
      started = true;
      return { analyzer: 'never-started', durationMs: 0, findings: [] };
    });
    const controller = new AbortController();
    controller.abort();

    const [result] = await new AnalyzerRunner().run([analyzer], {
      root: process.cwd(),
      signal: controller.signal
    });

    expect(result?.status).toBe('cancelled');
    expect(started).toBe(false);
  });

  it('stops an isolated analyzer on external cancellation', async () => {
    const dir = tmp();
    const file = path.join(dir, 'cancel.txt');
    writeFileSync(file, '');
    const controller = new AbortController();

    const running = new AnalyzerRunner({ timeoutMs: 60_000 }).run(
      [new SpinAnalyzer()],
      {
        root: dir,
        signal: controller.signal,
        options: { sideEffectFile: file }
      }
    );
    await waitForSize(file);
    controller.abort();
    const [result] = await running;

    expect(result?.status).toBe('cancelled');
    const after = size(file);
    await sleep(300);
    expect(size(file)).toBe(after);
  }, 30_000);

  it('cancels an in-flight network request when the deadline fires (socket is closed)', async () => {
    const closed = { value: false };
    const server = http.createServer(() => {
      // Never answer.
    });
    server.on('connection', (socket) => {
      socket.on('close', () => {
        closed.value = true;
      });
    });
    servers.push(server);
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;

    const network = inProcess('network', async (context) => {
      await fetch(`http://127.0.0.1:${port}/`, { signal: context.signal });
      return { analyzer: 'network', durationMs: 0, findings: [] };
    });

    const [result] = await new AnalyzerRunner({ timeoutMs: 100 }).run(
      [network],
      {
        root: process.cwd()
      }
    );

    expect(result?.status).toBe('timed_out');
    expect(result?.unresponsive).toBeUndefined(); // fetch honored the signal
    await sleep(200);
    expect(closed.value).toBe(true);
  });

  it('stops cooperative file I/O promptly after abort', async () => {
    const dir = tmp();
    const file = path.join(dir, 'io.txt');
    writeFileSync(file, '');
    const writer = inProcess('writer', async (context) => {
      while (!context.signal?.aborted) {
        appendFileSync(file, 'x');
        await sleep(1);
      }
      return { analyzer: 'writer', durationMs: 0, findings: [] };
    });

    const [result] = await new AnalyzerRunner({
      timeoutMs: 100,
      graceMs: 500
    }).run([writer], { root: dir });
    expect(result?.status).toBe('timed_out');

    const after = size(file);
    await sleep(100);
    expect(size(file)).toBe(after);
  });

  it('produces the same findings for the real AST analyzer in a worker as in-process', async () => {
    const dir = tmp();
    writeFileSync(
      path.join(dir, 'danger.ts'),
      'import { exec } from "node:child_process";\nexport function run(cmd: string) { eval(cmd); exec(cmd); }\n'
    );
    writeFileSync(path.join(dir, 'package.json'), '{"name":"x"}');

    const direct = await new AstSecurityAnalyzer().analyze({ root: dir });
    const [isolated] = await new AnalyzerRunner({ timeoutMs: 30_000 }).run(
      [new AstSecurityAnalyzer()],
      { root: dir }
    );

    expect(isolated?.status).toBe('ok');
    expect(isolated?.findings.map((f) => f.id).sort()).toEqual(
      direct.findings.map((f) => f.id).sort()
    );
    expect(direct.findings.length).toBeGreaterThan(0);
    expect(isolated?.coverage?.state).toBe('complete');
  }, 60_000);
});
