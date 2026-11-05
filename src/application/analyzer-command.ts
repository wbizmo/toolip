import type { Analyzer } from '../contracts/analyzer.js';

/** Test seams shared by the analyzer-facing commands. Defaults are the real analyzer and a 60 s deadline. */
export type AnalyzerCommandDeps = {
  analyzer?: Analyzer;
  timeoutMs?: number;
};
