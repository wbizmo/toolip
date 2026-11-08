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
