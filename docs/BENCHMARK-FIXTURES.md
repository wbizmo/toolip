# Benchmark fixture catalog

This catalog describes the deterministic local fixtures used for the
07–16 performance review. They are synthetic and designed to isolate named
input dimensions; they do not represent production repositories or establish
release readiness.

| Fixture                        | Varied input                                                                                            | Recorded behavior                                                                                    | Source / evidence                                                                                                                               |
| ------------------------------ | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Source walk and bounded reads  | 1k / 10k / 50k files, fixed-size source                                                                 | Cold/warm discovery, files opened, bytes read, heap/RSS and elapsed time                             | `npm run benchmark:scale -- 1000 10000 50000`; `docs/benchmarks/` JSONL                                                                         |
| Full offline scorecard         | Same source-file sizes plus manifest, lockfile and Git metadata                                         | Cold/warm findings, completeness, provider calls, cache hits/misses and process memory               | `docs/BENCHMARKS.md`; isolated scorecard JSONL                                                                                                  |
| AST/rule/byte scorecard        | Per-file byte target, exported symbols, 0–8 seeded AST rule IDs and seeded-file count                   | Per-rule planted-finding counts, complete coverage, source bytes and fixture digest                  | `TOOLIP_BENCHMARK_SOURCE_BYTES`, `TOOLIP_BENCHMARK_SYMBOLS_PER_FILE`, `TOOLIP_BENCHMARK_RULES`, `TOOLIP_BENCHMARK_SEEDED_FINDINGS`; smoke JSONL |
| Frozen Batch 09 resolver scale | 1k / 10k / 50k source files, 512 bytes/file, three declarations/file, eight seeded rule IDs in one file | One cold full-scorecard sample per size, findings/coverage/provider counts, CPU and sampled heap/RSS | `docs/benchmarks/toolip-v3.2.1-batch09-module-index-frozen-scale-2026-11-09-linux-node24.jsonl`; provenance and limits in `docs/BENCHMARKS.md`  |
| Concurrent scorecards          | 1–4 simultaneous full scans over one immutable snapshot                                                 | Per-scan result/coverage parity and process-level heap/RSS peak                                      | `TOOLIP_BENCHMARK_CONCURRENT_SCANS`; smoke JSONL                                                                                                |
| Wide dependency graph          | Resolved package vertex count with one direct edge per node                                             | Inventory and graph summary scaling                                                                  | `docs/benchmarks/` JSONL                                                                                                                        |
| Converging dependency graph    | Vertices and two outgoing edges per node                                                                | Shared-node queue/visited behavior, edge count, depth and queue counters                             | `tests/core/dependency-tree.test.ts`; benchmark JSONL                                                                                           |
| Secret-location processing     | Source lines and matching occurrences                                                                   | Current indexed cursor versus the retained reference algorithm; checksum equivalence                 | `docs/BENCHMARKS.md`; benchmark JSONL                                                                                                           |
| AST directory index            | Directory count and import-resolution queries                                                           | Index visits and timings versus the previous scan reference                                          | `docs/benchmarks/toolip-v3.2.1-ast-directory-index-linux-node24.jsonl`                                                                          |
| AST project cache              | 1k / 10k / 50k source files, 16-path chunks                                                             | Cold/warm wall time, chunk hits, scorecard completeness and sampled RSS                              | `docs/benchmarks/toolip-v3.2.1-isolated-ast-cache-2026-11-08-linux-node24.jsonl`                                                                |
| AST component analysis         | 1k / 10k / 50k independent TypeScript files                                                             | Cold/warm full scorecard, concurrent pair, one-file invalidation, coverage and RSS                   | `docs/benchmarks/toolip-v3.2.1-ast-components-2026-11-08-linux-node24.jsonl`                                                                    |
| Deep import digest graph       | 20,000 vertices in a chain and cyclic reordered inputs                                                  | Vertex/edge visits, explicit DFS frame bound and deterministic digest                                | AST source-analysis regression tests                                                                                                            |
| High-fan-in graph summary      | 768 reachable vertices, 131,072 edges                                                                   | Unique enqueue count and maximum live queue occupancy                                                | `tests/core/dependency-tree.test.ts`                                                                                                            |

The fixture runner records generated sizes and outcomes in JSONL. Rule seeds
are intentionally limited to eight fixed AST rules. Concurrent scorecard count
varies full scans, not the internal AST worker pool. The harness marks
time-to-first-finding unavailable because the scorecard API returns aggregate
results after analysis. The 2026-11-09 small dimension smoke is recorded in
`docs/benchmarks/toolip-v3.2.1-batch09-harness-smoke-2026-11-09-linux-node24.jsonl`;
it validates the controls but does not complete the independently varied
1k/10k/50k axis sweep or provide repeated p50/p95 results. The final Batch 09
module-index curve has one cold run at each 1k/10k/50k size; it does not fill
those broader evidence gaps.

The checked-in historical scorecard, AST-cache, and component-analysis records use a working-tree provenance label;
see [benchmark methodology](BENCHMARK-METHODOLOGY.md) and
[benchmarks](BENCHMARKS.md) for its scope. It must not be relabeled as a clean
commit run. The component-analysis records include one concurrent-pair sample
at each size and a three-iteration incremental sample at 1k; they do not
establish p50/p95 across repeated runs, full independent file-versus-byte/rule/
graph sweeps, or cross-platform behavior. Those remain acceptance work for
#40/#56/#86.
