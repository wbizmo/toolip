import { performance } from 'node:perf_hooks';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../contracts/analyzer.js';

export type AnalyzerRunnerOptions = {
  concurrency?: number;
  timeoutMs?: number;
};

export class AnalyzerRunner {
  private readonly concurrency: number;
  private readonly timeoutMs: number;

  constructor(options: AnalyzerRunnerOptions = {}) {
    this.concurrency = Math.max(1, options.concurrency ?? 4);
    this.timeoutMs = Math.max(1_000, options.timeoutMs ?? 30_000);
  }

  async run(
    analyzers: Analyzer[],
    context: AnalyzerContext
  ): Promise<AnalyzerResult[]> {
    const results: AnalyzerResult[] = [];
    let cursor = 0;

    const worker = async (): Promise<void> => {
      while (cursor < analyzers.length) {
        const analyzer = analyzers[cursor];
        cursor += 1;

        if (!analyzer) {
          return;
        }

        results.push(
          await this.runOne(analyzer, context)
        );
      }
    };

    await Promise.all(
      Array.from(
        { length: Math.min(this.concurrency, analyzers.length) },
        () => worker()
      )
    );

    return results;
  }

  private async runOne(
    analyzer: Analyzer,
    context: AnalyzerContext
  ): Promise<AnalyzerResult> {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      this.timeoutMs
    );
    const startedAt = performance.now();

    try {
      const result = await analyzer.analyze({
        ...context,
        signal: controller.signal
      });

      return {
        ...result,
        analyzer: analyzer.id,
        durationMs: Math.round(performance.now() - startedAt)
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}
