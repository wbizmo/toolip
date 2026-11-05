import { appendFileSync } from 'node:fs';
import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../../src/contracts/analyzer.js';

/**
 * Worker-isolated fixture analyzers for the AnalyzerRunner tests (issue #34).
 * They are loaded inside a worker thread by module URL + export name.
 */

/** Spins the CPU in a synchronous loop and keeps appending to a file. */
export class SpinAnalyzer implements Analyzer {
  readonly id = 'spin';
  readonly version = '1.0.0';
  readonly isolation = {
    module: import.meta.url,
    exportName: 'SpinAnalyzer'
  };

  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const target = String(context.options?.sideEffectFile);
    // Synchronous: no timer, promise or AbortSignal can interrupt this.
    for (;;) {
      appendFileSync(target, 'x');
    }
  }
}

/** Completes normally and returns a finding, to prove the worker path works. */
export class EchoAnalyzer implements Analyzer {
  readonly id = 'echo';
  readonly version = '1.0.0';
  readonly isolation = {
    module: import.meta.url,
    exportName: 'EchoAnalyzer'
  };

  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    return {
      analyzer: this.id,
      durationMs: 0,
      findings: [],
      metadata: { root: context.root, answer: 42 }
    };
  }
}

/** Throws inside the worker. */
export class ThrowingAnalyzer implements Analyzer {
  readonly id = 'throws';
  readonly version = '1.0.0';
  readonly isolation = {
    module: import.meta.url,
    exportName: 'ThrowingAnalyzer'
  };

  async analyze(): Promise<AnalyzerResult> {
    throw new Error('exploded inside the worker');
  }
}
