/**
 * Stable process exit codes for analysis commands (documented in
 * docs/ANALYSIS-STATUS.md). When several apply, the highest wins.
 */
export const EXIT_CODES = {
  /** Analysis complete and no finding at or above the gate. */
  ok: 0,
  /** Unexpected error (usage error, crash). */
  error: 1,
  /** Analysis complete; at least one finding met the `--fail-on` threshold. */
  findings: 2,
  /** Analysis partial: eligible inputs were not examined (with fail-on-incomplete). */
  incomplete: 3,
  /** Analysis failed, timed out or was cancelled. */
  failed: 4
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];
