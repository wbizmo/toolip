import { performance } from 'node:perf_hooks';
import { Worker } from 'node:worker_threads';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../contracts/analyzer.js';
import { mapConcurrent } from './concurrency.js';

export type AnalyzerRunnerOptions = {
  concurrency?: number;
  timeoutMs?: number;
  /**
   * How long an in-process analyzer may keep running after its deadline/abort
   * before it is reported as unresponsive. Default 100 ms.
   */
  graceMs?: number;
  /** V8 heap cap for isolated (worker) analyzers. Default 512 MiB. */
  workerMaxOldGenerationMb?: number;
};

export type AnalyzerExecutionStatus =
  'ok' | 'failed' | 'timed_out' | 'cancelled';

export type AnalyzerExecutionResult = AnalyzerResult & {
  status: AnalyzerExecutionStatus;
  error?: string;
  /**
   * True when an in-process analyzer ignored its AbortSignal and was still
   * running when the grace period ended: Node cannot stop it, so it may keep
   * consuming CPU or performing I/O. Declare `isolation` to make termination
   * enforceable.
   */
  unresponsive?: boolean;
};

export type AnalyzerRunnerStats = {
  /** Analyzer operations running right now (a slot is held until they stop). */
  active: number;
  peakActive: number;
};

type Outcome =
  | { kind: 'ok'; result: AnalyzerResult }
  | { kind: 'failed'; error: unknown }
  | { kind: 'timed_out' }
  | { kind: 'cancelled' };

/**
 * Runs analyzers with bounded concurrency and an enforced deadline.
 *
 * Cooperative in-process analyzers receive an AbortSignal and are given
 * `graceMs` to stop; if they do not, the result is `timed_out` with
 * `unresponsive: true` (their slot is released only after the grace period).
 * Analyzers that declare `isolation` run in a worker thread that is terminated
 * on deadline/abort, and the slot is released only after the thread has exited,
 * so a timed-out analyzer cannot keep running behind a free slot.
 *
 * Complexity: O(N) analyzers; at most `concurrency` operations are active.
 */
export class AnalyzerRunner {
  private readonly concurrency: number;
  private readonly timeoutMs: number;
  private readonly graceMs: number;
  private readonly workerMaxOldGenerationMb: number;
  private active = 0;
  private peakActive = 0;

  constructor(options: AnalyzerRunnerOptions = {}) {
    this.concurrency = Math.max(1, options.concurrency ?? 4);
    this.timeoutMs = Math.max(1, options.timeoutMs ?? 30_000);
    this.graceMs = Math.max(0, options.graceMs ?? 100);
    this.workerMaxOldGenerationMb = Math.max(
      16,
      options.workerMaxOldGenerationMb ?? 512
    );
  }

  get stats(): AnalyzerRunnerStats {
    return { active: this.active, peakActive: this.peakActive };
  }

  async run(
    analyzers: readonly Analyzer[],
    context: AnalyzerContext
  ): Promise<AnalyzerExecutionResult[]> {
    return mapConcurrent(analyzers, this.concurrency, (analyzer) =>
      this.runOne(analyzer, context)
    );
  }

  private async runOne(
    analyzer: Analyzer,
    context: AnalyzerContext
  ): Promise<AnalyzerExecutionResult> {
    const startedAt = performance.now();

    // Never begin new work once cancellation was requested.
    if (context.signal?.aborted) {
      return this.settle(analyzer, startedAt, { kind: 'cancelled' }, false);
    }

    this.active += 1;
    this.peakActive = Math.max(this.peakActive, this.active);

    try {
      const { outcome, unresponsive } = analyzer.isolation
        ? await this.execIsolated(analyzer, context)
        : await this.execInProcess(analyzer, context);
      return this.settle(analyzer, startedAt, outcome, unresponsive);
    } finally {
      this.active -= 1;
    }
  }

  private async execInProcess(
    analyzer: Analyzer,
    context: AnalyzerContext
  ): Promise<{ outcome: Outcome; unresponsive: boolean }> {
    const controller = new AbortController();
    let timeout: NodeJS.Timeout | undefined;
    let cancel: (() => void) | undefined;

    // Deadline and cancellation are installed before analysis starts.
    const deadline = new Promise<Outcome>((resolve) => {
      timeout = setTimeout(() => {
        controller.abort();
        resolve({ kind: 'timed_out' });
      }, this.timeoutMs);
    });

    const cancellation = new Promise<Outcome>((resolve) => {
      if (!context.signal) return;
      cancel = () => {
        controller.abort();
        resolve({ kind: 'cancelled' });
      };
      context.signal.addEventListener('abort', cancel, { once: true });
    });

    let settled = false;
    const analysis: Promise<Outcome> = Promise.resolve()
      .then(() => analyzer.analyze({ ...context, signal: controller.signal }))
      .then(
        (result): Outcome => ({ kind: 'ok', result }),
        (error): Outcome => ({ kind: 'failed', error })
      )
      .finally(() => {
        settled = true;
      });

    try {
      const outcome = await Promise.race([analysis, deadline, cancellation]);

      if (outcome.kind === 'timed_out' || outcome.kind === 'cancelled') {
        // Give a cooperative analyzer a moment to observe the abort; hold the
        // slot while it is still running, then flag it if it never stopped.
        await Promise.race([
          analysis,
          new Promise<void>((resolve) => setTimeout(resolve, this.graceMs))
        ]);
        return { outcome, unresponsive: !settled };
      }

      return { outcome, unresponsive: false };
    } finally {
      if (timeout) clearTimeout(timeout);
      if (cancel && context.signal) {
        context.signal.removeEventListener('abort', cancel);
      }
    }
  }

  private async execIsolated(
    analyzer: Analyzer,
    context: AnalyzerContext
  ): Promise<{ outcome: Outcome; unresponsive: boolean }> {
    const isolation = analyzer.isolation;
    if (!isolation) {
      return {
        outcome: { kind: 'failed', error: new Error('missing isolation') },
        unresponsive: false
      };
    }

    const { entry, execArgv } = workerEntry();
    let timeout: NodeJS.Timeout | undefined;
    let cancel: (() => void) | undefined;

    const worker = new Worker(entry, {
      workerData: {
        module: isolation.module,
        exportName: isolation.exportName,
        context: { root: context.root, options: context.options }
      },
      execArgv,
      resourceLimits: { maxOldGenerationSizeMb: this.workerMaxOldGenerationMb },
      stdout: false,
      stderr: false
    });

    const outcome = await new Promise<Outcome>((resolve) => {
      worker.once(
        'message',
        (message: { ok: boolean; result?: AnalyzerResult; error?: string }) => {
          resolve(
            message.ok && message.result
              ? { kind: 'ok', result: message.result }
              : {
                  kind: 'failed',
                  error: new Error(message.error ?? 'isolated analyzer failed')
                }
          );
        }
      );
      worker.once('error', (error) => resolve({ kind: 'failed', error }));
      worker.once('exit', (code) =>
        resolve({
          kind: 'failed',
          error: new Error(
            `isolated analyzer exited with code ${code} before returning a result`
          )
        })
      );

      timeout = setTimeout(
        () => resolve({ kind: 'timed_out' }),
        this.timeoutMs
      );

      if (context.signal) {
        cancel = () => resolve({ kind: 'cancelled' });
        if (context.signal.aborted) cancel();
        else context.signal.addEventListener('abort', cancel, { once: true });
      }
    });

    if (timeout) clearTimeout(timeout);
    if (cancel && context.signal) {
      context.signal.removeEventListener('abort', cancel);
    }

    // Enforceable stop: terminate() halts even a synchronous CPU loop and
    // resolves only after the thread has exited, so the slot is not freed early.
    await worker.terminate();

    return { outcome, unresponsive: false };
  }

  private settle(
    analyzer: Analyzer,
    startedAt: number,
    outcome: Outcome,
    unresponsive: boolean
  ): AnalyzerExecutionResult {
    const durationMs = Math.round(performance.now() - startedAt);

    if (outcome.kind === 'ok') {
      return {
        ...outcome.result,
        analyzer: analyzer.id,
        durationMs,
        status: 'ok'
      };
    }

    if (outcome.kind === 'timed_out') {
      return {
        analyzer: analyzer.id,
        durationMs,
        status: 'timed_out',
        error: `Analyzer exceeded its ${this.timeoutMs}ms deadline.`,
        findings: [],
        warnings: [
          `${analyzer.id} timed out.`,
          ...(unresponsive
            ? [
                `${analyzer.id} ignored cancellation and may still be running; declare worker isolation to make termination enforceable.`
              ]
            : [])
        ],
        unresponsive: unresponsive || undefined
      };
    }

    if (outcome.kind === 'cancelled') {
      return {
        analyzer: analyzer.id,
        durationMs,
        status: 'cancelled',
        error: 'Analyzer execution was cancelled.',
        findings: [],
        warnings: [`${analyzer.id} was cancelled.`],
        unresponsive: unresponsive || undefined
      };
    }

    const error =
      outcome.error instanceof Error
        ? outcome.error.message
        : String(outcome.error);

    return {
      analyzer: analyzer.id,
      durationMs,
      status: 'failed',
      error,
      findings: [],
      warnings: [`${analyzer.id} failed: ${error}`]
    };
  }
}

/**
 * Locates the worker entry next to this module. From TypeScript sources (tests,
 * `tsx`) a tiny bootstrap registers tsx in the worker first; the published
 * package uses the compiled `analyzer-worker.js` directly.
 */
function workerEntry(): { entry: URL; execArgv: string[] } {
  const fromSource = import.meta.url.endsWith('.ts');

  return fromSource
    ? {
        entry: new URL('./analyzer-worker-dev.mjs', import.meta.url),
        execArgv: []
      }
    : {
        entry: new URL('./analyzer-worker.js', import.meta.url),
        execArgv: []
      };
}
