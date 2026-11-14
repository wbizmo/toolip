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

The scale harness exposes bounded independent fixture controls:

- `TOOLIP_BENCHMARK_SOURCE_BYTES` sets the requested per-file byte target;
  seeded rule code and declarations can exceed that target, but a file above
  the scanner's 4,096-byte limit is rejected.
- `TOOLIP_BENCHMARK_SYMBOLS_PER_FILE` varies exported declarations (1–100).
- `TOOLIP_BENCHMARK_RULES` seeds 0–8 distinct AST rule patterns in each of the
  configured seeded files. The runner checks the expected count for each rule
  ID and records the total and per-rule results.
- `TOOLIP_BENCHMARK_SEEDED_FINDINGS` bounds the number of source files that
  contain those rule patterns (0–50,000).
- `TOOLIP_BENCHMARK_CONCURRENT_SCANS` varies simultaneous full scorecards
  (1–4); this is scan concurrency, not a configurable count of internal AST
  workers.
- `TOOLIP_BENCHMARK_GRAPH_FANOUT` varies converging lockfile graph density
  (1–8 outgoing edges per package).

The scorecard API returns findings only after analysis completes, so the
harness emits `timeToFirstFindingMs: null` with the reason. Do not infer a
first-finding latency from total scan time. The current scorecard fixture also
does not expose internal worker-pool sizing as a variable.

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

## Batch 09 harness smoke (2026-11-09)

After adding the independent symbol, source-byte target, seeded-rule,
concurrent-scorecard and graph-fanout controls, a small Linux Node 24.22.1
smoke run verified their row schema and seeded output checks. The full scorecard
fixture used four TypeScript files, a 512-byte target, three declarations per
file, eight planted AST rules in one file, and two concurrent scorecards. Both
scorecards completed; all eight rule IDs were detected once per scan, seven of
seven fixture files were covered by each scan, and provider requests were zero.
The concurrent pair took 895.79 ms with 53.7 MiB sampled heap peak and 357.6
MiB sampled RSS peak. A separate single cold scorecard run took 486.79 ms. After
the AST alias-flow correction, a fresh pair with the same fixture again
completed both scans and all eight planted-rule checks in each; that single
sample took 1.03 s with 51.9 MiB heap / 344.4 MiB RSS. Its raw row is preserved
in `toolip-v3.2.1-batch09-alias-flow-smoke-2026-11-09-linux-node24.jsonl`; the
first sample remains in the JSONL link below. The 20-node graph fixture used
fanout four and reported 70 edges with the same expected graph summary on cold
and warm passes. Raw evidence is
[`toolip-v3.2.1-batch09-harness-smoke-2026-11-09-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-batch09-harness-smoke-2026-11-09-linux-node24.jsonl).

These smoke fixtures verify harness behavior only. They are not the required
1k/10k/50k dimensional campaign, do not provide p50/p95, do not measure
time-to-first-finding, and do not qualify memory or release performance. No
additional 50k campaign was run; prior raw scale evidence remains preserved.

## Frozen Batch 09 resolver scale (2026-11-09)

The module-index change was measured once at 1k, 10k and 50k files after the
AST source and regression tests were frozen. The cold full-scorecard runs used
Linux x64 / Node 24.22.1, 512-byte source files, three exported symbols per
file, eight seeded rule patterns in one file, and offline providers. Each run
reported complete coverage, all eight findings detected and zero provider
requests. The raw artifact is
`docs/benchmarks/toolip-v3.2.1-batch09-module-index-frozen-scale-2026-11-09-linux-node24.jsonl`;
its SHA-256, fixture hashes and source/test/runner diff provenance are recorded
in `docs/BENCHMARKS.md`. This specific post-change sweep is one observation per
size, not repeated p50/p95 evidence, a memory bound or release qualification.
The earlier five-run 50k evidence was left untouched; no further repeat of that
campaign was made.
