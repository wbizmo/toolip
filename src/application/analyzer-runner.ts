import { performance } from 'node:perf_hooks';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../contracts/analyzer.js';
import { mapConcurrent } from './concurrency.js';

export type AnalyzerRunnerOptions = {
  concurrency?: number;
  timeoutMs?: number;
};

export type AnalyzerExecutionStatus =
  | 'ok'
  | 'failed'
  | 'timed_out'
  | 'cancelled';

export type AnalyzerExecutionResult = AnalyzerResult & {
  status: AnalyzerExecutionStatus;
  error?: string;
};

type Outcome =
  | { kind: 'ok'; result: AnalyzerResult }
  | { kind: 'failed'; error: unknown }
  | { kind: 'timed_out' }
  | { kind: 'cancelled' };

export class AnalyzerRunner {
  private readonly concurrency: number;
  private readonly timeoutMs: number;

  constructor(options: AnalyzerRunnerOptions = {}) {
    this.concurrency = Math.max(1, options.concurrency ?? 4);
    this.timeoutMs = Math.max(1, options.timeoutMs ?? 30_000);
  }

  async run(
    analyzers: readonly Analyzer[],
    context: AnalyzerContext
  ): Promise<AnalyzerExecutionResult[]> {
    return mapConcurrent(
      analyzers,
      this.concurrency,
      (analyzer) => this.runOne(analyzer, context)
    );
  }

  private async runOne(
    analyzer: Analyzer,
    context: AnalyzerContext
  ): Promise<AnalyzerExecutionResult> {
    const controller = new AbortController();
    const startedAt = performance.now();
    let timeout: NodeJS.Timeout | undefined;
    let cancel: (() => void) | undefined;

    const analysis: Promise<Outcome> = analyzer.analyze({
      ...context,
      signal: controller.signal
    }).then(
      (result) => ({ kind: 'ok', result }),
      (error) => ({ kind: 'failed', error })
    );

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

      if (context.signal.aborted) {
        cancel();
      } else {
        context.signal.addEventListener('abort', cancel, { once: true });
      }
    });

    try {
      const outcome = await Promise.race([
        analysis,
        deadline,
        cancellation
      ]);
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
          warnings: [`${analyzer.id} timed out.`]
        };
      }

      if (outcome.kind === 'cancelled') {
        return {
          analyzer: analyzer.id,
          durationMs,
          status: 'cancelled',
          error: 'Analyzer execution was cancelled.',
          findings: [],
          warnings: [`${analyzer.id} was cancelled.`]
        };
      }

      const error = outcome.error instanceof Error
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
    } finally {
      if (timeout) clearTimeout(timeout);
      if (cancel && context.signal) {
        context.signal.removeEventListener('abort', cancel);
      }
    }
  }
}
