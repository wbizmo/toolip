import { parentPort, workerData } from 'node:worker_threads';
import type { Analyzer, AnalyzerContext } from '../contracts/analyzer.js';

/**
 * Worker-thread entry used by AnalyzerRunner for analyzers that declare
 * `isolation` (issue #34). It constructs the named class, runs `analyze` once
 * and posts a structured-cloneable result. The parent terminates this thread at
 * the deadline, which stops even a synchronous CPU loop.
 */
type WorkerInput = {
  module: string;
  exportName: string;
  context: Pick<AnalyzerContext, 'root' | 'options'>;
};

async function main(): Promise<void> {
  const input = workerData as WorkerInput;

  try {
    const loaded = (await import(input.module)) as Record<string, unknown>;
    const Ctor = loaded[input.exportName] as (new () => Analyzer) | undefined;

    if (typeof Ctor !== 'function') {
      throw new Error(
        `Isolated analyzer export "${input.exportName}" was not found.`
      );
    }

    const result = await new Ctor().analyze(input.context);
    parentPort?.postMessage({ ok: true, result });
  } catch (error) {
    parentPort?.postMessage({
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
}

void main();
