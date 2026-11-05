import type { AnalysisCoverage } from './analysis.js';
import type { Finding } from './finding.js';

export type AnalyzerContext = {
  root: string;
  signal?: AbortSignal;
  cache?: AnalyzerCache;
  options?: Record<string, unknown>;
};

export type AnalyzerCache = {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttlMs?: number): Promise<void>;
};

export type AnalyzerResult = {
  analyzer: string;
  durationMs: number;
  findings: Finding[];
  warnings?: string[];
  metadata?: Record<string, unknown>;
  /** What was actually examined. Absent means the analyzer predates coverage reporting. */
  coverage?: AnalysisCoverage;
};

/**
 * Opt-in worker isolation (issue #34). A cooperative in-process analyzer cannot
 * be stopped if it ignores its AbortSignal or spins the CPU, so heavy or
 * untrusted analyzers name an importable module + exported class. The runner
 * constructs it inside a worker thread it can terminate at the deadline.
 * The class must have a no-argument constructor, and the context and result
 * must be structured-cloneable.
 */
export type AnalyzerIsolation = {
  /** Absolute `file:` URL of the module (usually `import.meta.url`). */
  module: string;
  exportName: string;
};

export interface Analyzer {
  readonly id: string;
  readonly version: string;
  readonly isolation?: AnalyzerIsolation;
  analyze(context: AnalyzerContext): Promise<AnalyzerResult>;
}
