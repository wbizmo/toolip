# Scale benchmark methodology

`npm run benchmark:scale -- 1000 10000 50000` creates deterministic temporary
source trees and npm lockfiles. It records cold and warm source discovery plus
bounded reads, an end-to-end offline scorecard over a complete generated Git
repository, wide dependency graphs, converging two-edge-per-node graphs, and
secret-match location processing. Each JSONL row includes platform, Node
version, wall time, user/system CPU time, heap/RSS deltas and sampled peaks,
file/byte counts, cache hits/misses where applicable, and provider request
count. Fixtures are removed after each size.

Secret-location output compares the current one-pass index/cursor implementation
against the previous repeated-prefix-split algorithm from
`cf94e2103e7d2ced05a0acf68251bcc8fd7ab125`. The old algorithm runs through
10,000 source lines; at 50,000 lines it is intentionally skipped because the
reference performs quadratic work. Matching checksums verify both paths
produce the same line and column positions. The graph fixture has two direct
packages and each package links to the next two, creating a large number of
converging paths without an exponential number of graph nodes.

## Recorded local run

The committed JSONL artifact was collected on Linux with Node v24.22.1 in this
working tree. It is a synthetic benchmark, not a full repository scan and not a
cross-platform claim. The process-level sampled heap/RSS peaks can include
garbage retained from earlier fixture passes; use them as observed process
ceilings, not isolated per-operation allocations. Provider requests were zero.

| Fixture                           | Size | Cold wall time | Warm wall time | Files opened / bytes read | Result                     |
| --------------------------------- | ---: | -------------: | -------------: | ------------------------: | -------------------------- |
| Source tree walk and bounded read |   1k |         198 ms |         165 ms |             1,000 / 54 KB | Complete                   |
| Source tree walk and bounded read |  10k |       1,646 ms |       1,623 ms |           10,000 / 540 KB | Complete                   |
| Source tree walk and bounded read |  50k |       7,406 ms |       6,479 ms |           50,000 / 2.7 MB | Complete                   |
| Wide npm graph                    |   1k |          13 ms |           8 ms |                1 lockfile | 1,000 direct               |
| Wide npm graph                    |  10k |          95 ms |          68 ms |                1 lockfile | 10,000 direct              |
| Wide npm graph                    |  50k |         509 ms |         448 ms |                1 lockfile | 50,000 direct              |
| Converging npm graph              |   1k |          19 ms |          13 ms |                1 lockfile | 1,998 edges; depth 1,000   |
| Converging npm graph              |  10k |         147 ms |         150 ms |                1 lockfile | 19,998 edges; depth 10,000 |
| Converging npm graph              |  50k |         862 ms |         805 ms |                1 lockfile | 99,998 edges; depth 50,000 |

At 1,000 lines and 200 matches, the current location pass took 1.16 ms and the
legacy reference took 5.16 ms. At 10,000 lines and 2,000 matches, those passes
took 2.98 ms and 328.16 ms. Both reported identical location checksums. The
50,000-line legacy reference is skipped because its repeated prefix splitting
is quadratic. These measurements describe this machine and fixture; CI
thresholds require stable, documented runner hardware before they are made
gating.

The end-to-end scorecard fixture contains the requested TypeScript source
files plus a package manifest, empty lockfile and `.gitignore`. Each measured
pass includes one filesystem discovery, immutable snapshot creation, all
Security Doctor passes, dependency graph analysis, vulnerability analysis in
offline mode, and Git audit. Both cold and warm scorecards must report complete
analysis and coverage with zero findings. This is still a generated fixture,
not a production repository or a cross-platform measurement.

| Full scorecard fixture | Source files | Pass | Wall time | Files opened / bytes read | Cache hits / misses | Sampled heap peak | Sampled RSS peak |
| ---------------------- | -----------: | ---- | --------: | ------------------------: | ------------------: | ----------------: | ---------------: |
| Linux, Node 24.22.1    |        1,000 | cold |    1.03 s |             1,003 / 54 KB |           0 / 1,004 |           108 MiB |          368 MiB |
| Linux, Node 24.22.1    |        1,000 | warm |    397 ms |                     0 / 0 |           1,004 / 0 |           104 MiB |          376 MiB |
| Linux, Node 24.22.1    |       10,000 | cold |    4.20 s |           10,003 / 540 KB |          0 / 10,004 |           206 MiB |          538 MiB |
| Linux, Node 24.22.1    |       10,000 | warm |    1.17 s |                     0 / 0 |          10,004 / 0 |           359 MiB |          590 MiB |
| Linux, Node 24.22.1    |       50,000 | cold |   17.45 s |          50,003 / 2.70 MB |          0 / 50,004 |           689 MiB |        1,103 MiB |
| Linux, Node 24.22.1    |       50,000 | warm |    4.78 s |                     0 / 0 |          50,004 / 0 |           714 MiB |        1,252 MiB |

The complete JSONL run is saved at
[`docs/benchmarks/toolip-v3.2.1-full-repository-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-full-repository-linux-node24.jsonl).
The warm pass reuses all captured files and source findings. Sampled process
peaks include retained state from earlier passes in this process and are
conservative ceilings, not isolated allocations. The measurement is local to
Linux with Node 24.22.1; it makes no claim about Node 22, Windows, macOS or
other machines.

`maxDepth` retains longest-path semantics for acyclic dependency graphs using a
topological dynamic program. A graph containing a cycle uses maximum shortest
root distance instead, so cycle handling remains bounded rather than attempting
the NP-hard longest-simple-path problem. Direct/transitive counts remain based
on the reachable identity set in both cases.

The one-million-file release benchmark is reserved for final release
validation and has not been run.

## Post-audit exact-commit rerun (2026-11-08)

After the Maven parser and AST cache validation correction, the 1k/10k/50k
synthetic suite was rerun on clean source commit
`5b4cc7e8b15572b8c014cf8920b2dea208c61d42` with Linux Node 24.22.1. The raw
36-row result is
[`toolip-v3.2.1-post-audit-5b4cc7e-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-post-audit-5b4cc7e-linux-node24.jsonl).
Each size records one cold/warm pair; p50/p95 across repetitions is not
available. RSS is the isolated fixture process peak, including retained state
across the cold and warm scorecard passes.

| Offline scorecard   | Source files |      Cold / warm | Cold / warm sampled RSS | Result                                                      |
| ------------------- | -----------: | ---------------: | ----------------------: | ----------------------------------------------------------- |
| Linux, Node 24.22.1 |        1,000 |  1.51 s / 106 ms |           441 / 418 MiB | Complete; 0 provider calls                                  |
| Linux, Node 24.22.1 |       10,000 |  4.86 s / 488 ms |           610 / 601 MiB | Complete; 0 provider calls                                  |
| Linux, Node 24.22.1 |       50,000 | 20.19 s / 2.26 s |       1,110 / 1,133 MiB | Complete; 0 provider calls; 3,125/3,125 AST chunks hit warm |

At 50k the scan covered 50,003 files and read 2,700,244 bytes. The observed
process RSS remains high and warm RSS is higher than cold in this sample; this
does not establish a memory improvement or bound. These results cover the
exact source commit shown above and are synthetic local measurements, not
release qualification or cross-platform evidence.

## Isolated fixture process run (local resolver work)

An additional run was collected at local commit `41a3a9319b19bfb2c2290bafd1bb9fab794ddcd0`
on Linux with Node v24.22.1. The runner starts a child process for each
independent fixture and size so memory from earlier fixture sizes cannot
accumulate into later ones. Cold and warm passes for a scorecard size share one
child process because the warm pass intentionally measures retained snapshot
and analysis-cache state. Its sampled process peak therefore includes live and
retained state across those two passes; it is not an incremental allocation
measurement. This is a synthetic local benchmark, not release qualification.

| Fixture                           | Size | Cold wall time | Warm wall time | Files opened / bytes read | Result                      |
| --------------------------------- | ---: | -------------: | -------------: | ------------------------: | --------------------------- |
| Source tree walk and bounded read |   1k |         204 ms |         160 ms |    1,000 / 54 KB per pass | Complete                    |
| Source tree walk and bounded read |  10k |         1.37 s |         1.41 s |  10,000 / 540 KB per pass | Complete                    |
| Source tree walk and bounded read |  50k |         6.55 s |         6.05 s | 50,000 / 2.70 MB per pass | Complete                    |
| Wide npm graph                    |   1k |          24 ms |           9 ms |                1 lockfile | 1,000 direct; 1,000 edges   |
| Wide npm graph                    |  10k |         104 ms |          89 ms |                1 lockfile | 10,000 direct; 10,000 edges |
| Wide npm graph                    |  50k |         544 ms |         541 ms |                1 lockfile | 50,000 direct; 50,000 edges |
| Converging npm graph              |   1k |          33 ms |          13 ms |                1 lockfile | 1,998 edges; depth 1,000    |
| Converging npm graph              |  10k |         213 ms |         158 ms |                1 lockfile | 19,998 edges; depth 10,000  |
| Converging npm graph              |  50k |         1.07 s |         900 ms |                1 lockfile | 99,998 edges; depth 50,000  |

The full scorecard reported complete coverage at all three sizes and made zero
provider requests. The 50k cold pass took 19.97 s and opened 50,003 files
(2.70 MB); the warm pass took 7.35 s, reopened zero files and reused 50,003
snapshot entries and 50,004 cache entries. The observed scorecard process peak
at 50k was 362 MiB heap and 1,394 MiB RSS on the warm pass. This memory peak is
material and remains an optimization/audit item; it must not be presented as
bounded per-operation memory or as release verification. At 1k, 10k and 50k,
the cold/warm scorecard times were 1.64/1.23 s, 4.95/2.14 s and 19.97/7.35 s.

The optimized secret-location pass took 1.33 ms, 5.04 ms and 25.06 ms for 1k,
10k and 50k lines. The legacy repeated-prefix-split reference took 3.66 ms at
1k and 336.71 ms at 10k; it was skipped at 50k due to quadratic work. Current
and reference checksums matched where both ran.

The exact 30-row JSONL evidence is saved at
[`docs/benchmarks/toolip-v3.2.1-isolated-combined-41a3a93-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-isolated-combined-41a3a93-linux-node24.jsonl).
Rows identify the source commit, platform, runtime and fixture process scope.
These figures are specific to this machine and generated inputs; they do not
establish macOS/Windows results or acceptance of #40/#86.

## AST source-directory lookup regression

The TypeScript compiler host previously answered every `getDirectories` query
by scanning its complete set of known source directories. With `L` known
directories and `Q` queries, that costs `O(L × Q)` candidate visits. It now
builds a parent-to-child index in expected `O(L)` time and space, then answers
each query with an expected `O(1)` lookup plus the size of the returned child
list. The isolated synthetic benchmark compares both implementations using
independent Node v24.22.1 processes for each fixture size:

| Directories | Indexed time / visits |                   Prior scan time / visits |
| ----------: | --------------------: | -----------------------------------------: |
|          1k |       1.36 ms / 1,002 |                         937 ms / 1,003,002 |
|         10k |     10.84 ms / 10,002 |                      92.33 s / 100,030,002 |
|         50k |     27.71 ms / 50,002 | Skipped; quadratic reference capped at 10k |

Each indexed run returned the same 1k/10k/50k direct-child entries. The
deterministic 512-directory AST regression also verifies cross-file import
resolution and dependency-digest invalidation. These are isolated synthetic
directory-query measurements, not full AST or repository scan performance.
The machine-readable rows are in
[`docs/benchmarks/toolip-v3.2.1-ast-directory-index-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-ast-directory-index-linux-node24.jsonl).
The candidate source was a local worktree based on
`41a3a9319b19bfb2c2290bafd1bb9fab794ddcd0`; the SHA-256 of the binary Git diff
for the source implementation, benchmark runner and regression test is
`81a2cfcb0e69d78e970eb4728fba91ff6c0c795e159e7e6f04585accc7fa76d6`.

## Latest isolated 1k/10k/50k run after AST bounds

After the AST directory index, iterative SCC traversal and explicit AST depth
and node budgets were added, the complete scale harness was rerun. All 36
JSONL records are in
[`docs/benchmarks/toolip-v3.2.1-isolated-ast-bounds-2026-11-08-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-isolated-ast-bounds-2026-11-08-linux-node24.jsonl).
Each fixture and size used its own process; cold and warm scorecard passes
share that fixture process to retain the snapshot and cache intentionally. The
candidate is the local worktree based on `41a3a9319b19bfb2c2290bafd1bb9fab794ddcd0`;
the SHA-256 of its source, benchmark and regression-test diff is
`1e53aa70e152b7fec41a9e201b9dadabf10897f0b82dbb6997e6973810421b53`.

| Full scorecard   | Cold time / RSS peak | Warm time / RSS peak | Coverage and work                                                  |
| ---------------- | -------------------: | -------------------: | ------------------------------------------------------------------ |
| 1k source files  |     1.67 s / 426 MiB |     1.27 s / 490 MiB | Complete; 1,003 files; 54 KB cold reads; zero provider requests    |
| 10k source files |     4.96 s / 614 MiB |     2.14 s / 727 MiB | Complete; 10,003 files; 540 KB cold reads; zero provider requests  |
| 50k source files |  19.95 s / 1,098 MiB |   7.07 s / 1,188 MiB | Complete; 50,003 files; 2.70 MB cold reads; zero provider requests |

This run's 50k warm peak RSS was about 149 MiB (10.7%) below the prior
isolated run's 1,394 MiB peak, but this is a single synthetic sample on one
machine and does not establish a stable improvement threshold. The 1,188 MiB
peak remains material and whole-scan AST/snapshot/cache lifetime analysis is
still open. It is not release qualification. The new AST directory fixture
reports indexed times of 0.99/9.66/30.5 ms with 1,002/10,002/50,002 visits; its
legacy scan used 998.55 ms at 1k and 97.47 s at 10k, then was skipped at 50k.

## High-fan-in graph queue regression

`tests/dependency-tree.test.ts` includes a deterministic graph-summary fixture
with 256 direct nodes, 512 shared reachable nodes, and 131,072 fan-in edges.
The traversal records the number of enqueued vertices and peak live queue
entries; both must remain bounded by the 768 reachable vertices. Marking each
vertex reachable when it is enqueued prevents duplicate queue records before
the first dequeue. The summary pass is expected `O(V + E)` time with `O(V)`
additional queue, visited, indegree, and depth state; the caller-owned
adjacency is `O(V + E)` and is excluded from that additional-space figure.
This is a deterministic resource-bound regression, not a wall-clock benchmark
or a substitute for the phase-gated scale campaigns.

## Snapshot invalidation soak

`npm run soak:analysis` repeatedly changes one tracked source file and runs the
offline Security Scorecard over the same generated repository. Every iteration
must report complete analysis and coverage; after the first pass, the snapshot
must reuse all unchanged inputs while rereading the changed file. The shared
analysis cache is retained across iterations to exercise invalidation, reuse,
and cleanup over time. JSON output includes iteration latency percentiles,
peak RSS, snapshot reads/reuses, and cache hit/miss totals. The runner is
intentionally opt-in and bounded to at most 500 iterations and 2,000 source
files; set `SOAK_ITERATIONS`, `SOAK_FILES`, or `SOAK_MAX_RSS_MB` to adjust the
run within those limits. It performs no provider requests and does not execute
repository scripts. This exercises repeated snapshot and scorecard operation;
it does not replace dedicated Windows/macOS or process-crash testing.

## AST project cache memory investigation

The scorecard rebuilt its TypeScript project on every warm pass even when the
immutable source snapshot was unchanged. `Security Doctor` now caches the
whole-project AST findings and dependency digests in 16-path chunks, keyed by
the root and a digest over every eligible source path and content hash. The
existing analysis cache still enforces its 64 MiB total and 4 MiB per-entry
limits. A project result is reused only when every expected chunk is present
and validates its complete path list; missing, oversized or malformed chunks
fall back to the worker. Cache space is therefore bounded by the existing
cache budget, in addition to the snapshot and result data already retained.

An isolated Linux Node 24.22.1 50k scorecard run is recorded in
[`docs/benchmarks/toolip-v3.2.1-ast-cache-memory-50k-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-ast-cache-memory-50k-linux-node24.jsonl).
The cold pass analyzed all 50,003 files in 18.87 s, read 2.70 MB, and missed
all 3,125 AST chunks. The warm pass opened and read no files, reused all 3,125
AST chunks plus 50,004 per-file cache entries, and took 2.39 s. Both reported
complete coverage and zero findings/provider requests. Against the preceding
isolated 50k sample (7.07 s warm, 1,188 MiB sampled RSS and 299 MiB heap), this
sample's warm pass took 2.39 s with 1,116 MiB RSS and 423 MiB heap. The lower
sampled RSS and faster warm pass came with higher sampled heap; the cache
retains serialized results. A second run measured 1,143 MiB RSS and 440 MiB
heap, so the observed RSS reduction is not stable enough to set a guarantee.
Worker telemetry during the repeated cold pass recorded 1,041 MiB RSS at
project build and 1,047 MiB after per-file analysis. The change avoids
rebuilding that AST project on a cache hit; cold AST construction remains a
major memory cost. These are synthetic single-machine samples, not release
qualification or a complete memory bound. The benchmark diff includes the
AST cache hit/miss counters so a warm pass cannot be mistaken for worker
reuse.

The refreshed full 1k/10k/50k harness is in
[`docs/benchmarks/toolip-v3.2.1-isolated-ast-cache-2026-11-08-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-isolated-ast-cache-2026-11-08-linux-node24.jsonl).
It ran each fixture and size in its own process. Each scorecard reported
complete coverage, zero findings and zero provider requests; the warm pass
hit every AST chunk and per-file cache entry.

| Full scorecard   | Cold time / RSS peak | Warm time / RSS peak |       Warm AST cache |
| ---------------- | -------------------: | -------------------: | -------------------: |
| 1k source files  |     1.51 s / 423 MiB |     113 ms / 398 MiB |       63 / 63 chunks |
| 10k source files |     5.38 s / 612 MiB |     507 ms / 596 MiB |     625 / 625 chunks |
| 50k source files |  19.40 s / 1,099 MiB |   2.17 s / 1,117 MiB | 3,125 / 3,125 chunks |

The 50k sample's warm peak was 71 MiB below the preceding 1,188 MiB sample;
other repeated cache runs measured 1,116 and 1,143 MiB. Peak heap also varied
between 307 and 440 MiB. These samples show warm worker reuse and a variable
RSS reduction, while cache retention increases heap in some runs; they do not
support a hard memory guarantee. The indexed AST directory fixture in this
run measured 0.88/7.24/40.76 ms at 1k/10k/50k, with 1,002/10,002/50,002 index
visits. Its scan reference measured 963 ms at 1k and 92.39 s at 10k, then was
skipped at 50k by the configured quadratic-work cap.

## AST component memory and concurrent scans (2026-11-08)

The AST worker now builds the local import graph and analyzes one weakly
connected module component at a time. Script files, declaration files, ambient
modules, and global augmentations retain a project-wide TypeScript Program so
component splitting does not change their shared symbol environment. The
immutable snapshot remains capped at 50,000 files and 64 MiB; checker memory is
bounded by the largest processed component for eligible module-only inputs.
See [AST security analysis](AST-SECURITY.md) for the limits and fallback.

Linux Node 24.22.1 scorecard measurements use independent generated fixtures
with 1k/10k/50k TypeScript files. Every cold, warm, and incremental result had
complete scorecard and coverage states, zero findings, and zero provider
requests. A concurrent row runs two scorecards at once over the same immutable
snapshot. A separate three-iteration soak changes one file per scan at 1k.
Raw output is
[`toolip-v3.2.1-ast-components-2026-11-08-linux-node24.jsonl`](benchmarks/toolip-v3.2.1-ast-components-2026-11-08-linux-node24.jsonl).

| Source files | Cold / warm / one-file incremental time | Sampled RSS peaks, cold / warm / incremental | Snapshot reads in incremental | Concurrent pair RSS peak |
| -----------: | --------------------------------------: | -------------------------------------------: | ----------------------------: | -----------------------: |
|           1k |                0.94 s / 105 ms / 647 ms |                          369 / 349 / 404 MiB |              1 file, 58 bytes |                  492 MiB |
|          10k |                4.64 s / 531 ms / 1.56 s |                          554 / 543 / 688 MiB |              1 file, 58 bytes |                  842 MiB |
|          50k |               17.05 s / 2.24 s / 5.22 s |                        867 / 907 / 1,136 MiB |              1 file, 58 bytes |                1,282 MiB |

The 50k incremental run reused 50,002 snapshot files and hit 50,003 ordinary
analysis-cache entries, but conservatively rebuilt all 3,125 AST project
chunks because the project cache key covers the whole snapshot. Fine-grained
AST cache invalidation remains a performance opportunity; no stale AST result
was reused. The concurrent 50k pair scanned 50,003 files per run and both
reports remained complete. Compared with the earlier isolated 50k sample
(1,110 MiB cold and 1,133 MiB warm sampled RSS), this run observed lower cold
and warm peaks, but each is a single synthetic sample. Incremental and
concurrent measurements show that peak memory still reaches about 1.1 and 1.3
GiB respectively. These measurements do not establish a stable threshold,
release readiness, or cross-platform behavior.

The benchmark artifact is a dirty-tree measurement based on
`29f4c997d9314555b76011d49c72a298731a0172`. The SHA-256 of the source,
test, and benchmark-harness diff at measurement time is
`b2988d9b872bbd51f399df688d09b1c6588ca8ff0ae8d9fc47c247d78d620b14`.
Sequential runs used
`TOOLIP_BENCHMARK_ISOLATED=true node --import tsx scripts/benchmark-dependency-graph.ts --worker repository-scorecard SIZE`;
concurrent runs used the same command with
`repository-scorecard-concurrent`; the 1k soak used
`SOAK_ITERATIONS=3 SOAK_FILES=1000 npm run soak:analysis`. The raw rows retain
their `working-tree` label; this is not a clean commit run.

## Component-aware AST cache invalidation (2026-11-08)

After the cache invalidation correction, the same synthetic repository
scorecard now retains unaffected AST chunks when one independent source file
changes. The incremental run at each size reported one cache miss and exactly
one AST project-cache miss. It completed with full scan coverage and no
provider requests.

| Source files | Cold / warm / incremental | AST cache hits / chunks on incremental | Incremental sampled RSS peak |
| -----------: | ------------------------: | -------------------------------------: | ---------------------------: |
|        1,000 |      1.43 / 0.61 / 0.94 s |                                62 / 63 |                      451 MiB |
|       10,000 |      4.78 / 1.39 / 1.75 s |                              624 / 625 |                      675 MiB |
|       50,000 |     20.51 / 4.52 / 4.57 s |                          3,124 / 3,125 |                    1,210 MiB |

The measurements use one Linux Node 24.22.1 process per size, one cold, warm
and incremental pass, and process-level sampled memory peaks. The synthetic
fixture edits one independent file; changes to connected imports rerun that
weak component and its importers. Script/global-declaration fallback still
invalidates the project-wide component. The benchmark is one sample per size,
not a release qualification or memory guarantee. See the raw
[`AST cache invalidation JSONL`](benchmarks/toolip-v3.2.1-ast-cache-invalidation-2026-11-08-linux-node24.jsonl)
and [`complexity audit`](COMPLEXITY-AUDIT.md).

## Concurrent 50k scorecards (2026-11-08)

A single Linux Node 24.22.1 process ran two simultaneous offline scorecards on
the same immutable 50k-file snapshot, each with its own analysis cache. Both
scans reported complete coverage and zero provider requests. The pair took
11.73 s, with sampled process peaks of 477 MiB heap and 1,366 MiB RSS. For
comparison, the single cold pass at this size peaked at 932 MiB RSS in its own
process. This one-shot synthetic result shows concurrency increases process
memory materially; it does not establish a general cap or p50/p95 behavior.
The raw row is in
[`concurrent 50k JSONL`](benchmarks/toolip-v3.2.1-concurrent-memory-50k-linux-node24.jsonl).

## Scorecard without an analysis cache (2026-11-08)

The default uncached scorecard path analyzes the complete AST input once in its
bounded worker and skips the separate component-planning worker, avoiding a
second full-source structured clone when no cache can use that plan. Linux
Node 24.22.1 synthetic cold runs reported complete coverage and zero provider
requests at all three sizes.

| Source files | Wall time | Files opened / bytes | Sampled heap / RSS peak |
| -----------: | --------: | -------------------: | ----------------------: |
|        1,000 |    1.03 s |        1,003 / 54 KB |            75 / 356 MiB |
|       10,000 |    4.12 s |      10,003 / 540 KB |           107 / 584 MiB |
|       50,000 |   17.29 s |     50,003 / 2.70 MB |           245 / 835 MiB |

The raw one-pass measurements are in
[`no-cache scorecard JSONL`](benchmarks/toolip-v3.2.1-no-cache-scorecard-2026-11-08-linux-node24.jsonl).
These are single synthetic samples; the earlier cache-enabled cold runs use a
different path and are not an apples-to-apples before/after comparison. The
change removes a redundant plan worker by construction, but broader memory,
concurrency and repeated-run acceptance remains open.

### Cache-enabled cold scan now analyzes once (2026-11-08)

When the AnalysisResultCache contains no AST chunks for the scan, the AST worker
now returns findings plus component and dependency digests in one pass. Security
Doctor uses those results to seed the normal path-stable chunks. Warm and
partially populated caches retain the existing plan-and-reuse path. This avoids
cloning the full source set to a plan worker before sending it to the analysis
worker on a cold cache-enabled scan.

One isolated Linux Node 24.22.1 50k-file run reported 18.29 s / 899 MiB sampled
RSS cold, 4.41 s / 1,047 MiB warm, and 4.54 s / 1,260 MiB incremental. All
50,003 discovered files had complete coverage; the incremental independent
file edit reused 3,124 of 3,125 AST chunks. The prior cold sample in this
benchmark family measured 20.51 s / 932 MiB RSS, but these are single samples
and do not establish a repeatable improvement or bound. The warm and
incremental RSS observations also remain high. Raw rows:
[`cache-enabled cold worker JSONL`](benchmarks/toolip-v3.2.1-ast-cache-cold-worker-2026-11-08-linux-node24.jsonl).
