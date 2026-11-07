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
