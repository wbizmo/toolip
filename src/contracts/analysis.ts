/**
 * Canonical completeness model (issues #27, #35). "Complete" means every
 * eligible input was analyzed; a zero-finding partial run is NOT an all-clear.
 */
export const analysisStates = ['complete', 'partial', 'failed'] as const;
export type AnalysisState = (typeof analysisStates)[number];

export type AnalysisCoverage = {
  state: AnalysisState;
  /** Human-readable reason when state is not complete. */
  reason?: string;
  /** Inputs the analyzer is supposed to examine (excluding conscious exclusions). */
  eligible: number;
  scanned: number;
  /** Eligible inputs not examined (oversized, binary, budget, cancelled…). */
  skipped: number;
  /** Eligible inputs whose read/analysis raised an error. */
  failed: number;
  /** Inputs deliberately out of scope (unsupported types, ignore files). */
  excluded?: number;
};

export function coverageOf(input: {
  eligible: number;
  scanned: number;
  skipped: number;
  failed: number;
  excluded?: number;
  cancelled?: boolean;
}): AnalysisCoverage {
  const { eligible, scanned, skipped, failed, excluded, cancelled } = input;
  const unexamined = skipped + failed;

  if (eligible > 0 && scanned === 0 && unexamined > 0) {
    return {
      state: 'failed',
      reason: `none of ${eligible} eligible input(s) could be analyzed`,
      eligible,
      scanned,
      skipped,
      failed,
      excluded
    };
  }

  if (unexamined > 0 || cancelled) {
    return {
      state: 'partial',
      reason: cancelled
        ? 'analysis was cancelled before every eligible input was examined'
        : `${unexamined} of ${eligible} eligible input(s) were not analyzed`,
      eligible,
      scanned,
      skipped,
      failed,
      excluded
    };
  }

  return { state: 'complete', eligible, scanned, skipped, failed, excluded };
}
