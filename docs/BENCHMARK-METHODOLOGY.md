# Benchmark methodology

This document defines how local performance evidence for Batches 07–16 is
collected. Benchmark results are diagnostic evidence; they are not release
qualification or a substitute for supported-platform CI.

## Harness and controls

Use the checked-in `benchmark:scale` script and preserve its JSONL output under
`docs/benchmarks/`. Run each requested size in an isolated child process where
the harness supports it. Record the operating system, architecture, exact Node
version, input size, wall time, user/system CPU, sampled heap and RSS peaks,
files/bytes read, cache hits/misses, provider requests, completion state and
fixture checksum. Do not compare measurements from different hardware as if
they were controlled repetitions. Keep network providers disabled for local
synthetic scorecard runs.

For variance-sensitive comparisons, repeat the identical fixture at least
five times and report median and p95 as well as every raw sample. Separate cold,
warm, one-file invalidation, cache-eviction and concurrent-scan runs. Report
per-process peak RSS as an observed ceiling; it includes runtime and retained
state and is not a direct measure of one operation's allocation. Do not create
regression thresholds until runner hardware and natural variance have been
measured and reviewed.

## Provenance

Never replace a historical `gitSha` label with a later commit. For a dirty-tree
measurement, retain its original label and record the base commit, exact source
diff hash, fixture revision, command and environment in the report. A clean
commit measurement records the commit SHA and a clean-tree assertion. If source
or fixtures change, collect new evidence or clearly state that older numbers
do not cover those changes. `docs/BENCHMARKS.md` is the narrative index and the
JSONL artifact is the raw record.

## Interpretation and phase boundaries

Report output equivalence and completeness beside speed and memory. A faster
run that skips inputs, loses findings, changes exact dependency identities or
reports unknown inputs as clean is a failed measurement. The in-batch 1k/10k/
50k suite is distinct from the post-merge 100k/250k campaign assigned to #110
and the final release scale campaign assigned to #55. Do not run those later
campaigns as evidence for this PR.
