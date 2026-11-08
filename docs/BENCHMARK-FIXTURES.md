# Benchmark fixture catalog

This catalog describes the deterministic local fixtures used for the
07–16 performance review. They are synthetic and designed to isolate named
input dimensions; they do not represent production repositories or establish
release readiness.

| Fixture                       | Varied input                                                    | Recorded behavior                                                                      | Source / evidence                                                                |
| ----------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Source walk and bounded reads | 1k / 10k / 50k files, fixed-size source                         | Cold/warm discovery, files opened, bytes read, heap/RSS and elapsed time               | `npm run benchmark:scale -- 1000 10000 50000`; `docs/benchmarks/` JSONL          |
| Full offline scorecard        | Same source-file sizes plus manifest, lockfile and Git metadata | Cold/warm findings, completeness, provider calls, cache hits/misses and process memory | `docs/BENCHMARKS.md`; isolated scorecard JSONL                                   |
| Wide dependency graph         | Resolved package vertex count with one direct edge per node     | Inventory and graph summary scaling                                                    | `docs/benchmarks/` JSONL                                                         |
| Converging dependency graph   | Vertices and two outgoing edges per node                        | Shared-node queue/visited behavior, edge count, depth and queue counters               | `tests/core/dependency-tree.test.ts`; benchmark JSONL                            |
| Secret-location processing    | Source lines and matching occurrences                           | Current indexed cursor versus the retained reference algorithm; checksum equivalence   | `docs/BENCHMARKS.md`; benchmark JSONL                                            |
| AST directory index           | Directory count and import-resolution queries                   | Index visits and timings versus the previous scan reference                            | `docs/benchmarks/toolip-v3.2.1-ast-directory-index-linux-node24.jsonl`           |
| AST project cache             | 1k / 10k / 50k source files, 16-path chunks                     | Cold/warm wall time, chunk hits, scorecard completeness and sampled RSS                | `docs/benchmarks/toolip-v3.2.1-isolated-ast-cache-2026-11-08-linux-node24.jsonl` |
| Deep import digest graph      | 20,000 vertices in a chain and cyclic reordered inputs          | Vertex/edge visits, explicit DFS frame bound and deterministic digest                  | AST source-analysis regression tests                                             |
| High-fan-in graph summary     | 768 reachable vertices, 131,072 edges                           | Unique enqueue count and maximum live queue occupancy                                  | `tests/core/dependency-tree.test.ts`                                             |

The fixture runner records generated sizes and outcomes in JSONL. The checked-in
historical scorecard and AST-cache record uses a working-tree provenance label;
see [benchmark methodology](BENCHMARK-METHODOLOGY.md) and
[benchmarks](BENCHMARKS.md) for its scope. It must not be relabeled as a clean
commit run. These fixtures do not yet establish p50/p95 across repeated runs,
independent file-versus-byte/graph variation, multi-scan peak memory, or
cross-platform behavior. Those remain acceptance work for #40/#56/#86.
