# Toolip complexity audit — in progress

This is a working audit for issues #40, #56 and #86, not a completion or
release qualification. It records source-derived bounds that have a concrete
implementation or regression check, and names unresolved paths. Hash-map
figures below describe expected/amortized JavaScript `Map`/`Set` behavior;
they are not a claim of deterministic worst-case constant-time hashing.

## Dimensions

| Symbol   | Input                                                                      |
| -------- | -------------------------------------------------------------------------- |
| `F`      | discovered or changed file entries                                         |
| `B`      | accepted source, lockfile, Git-object and response bytes, stated per stage |
| `V`, `E` | dependency or execution graph vertices and edges                           |
| `S`      | AST symbols and references                                                 |
| `M`      | secret matches                                                             |
| `R`      | findings and serialized report bytes, as applicable                        |
| `C`      | bounded concurrent workers or provider requests                            |
| `P`      | provider requests including retries                                        |
| `H`      | history records or commits                                                 |
| `D`      | maximum input or graph depth                                               |
| `L`, `Q` | unique source directories and TypeScript directory queries                 |

The limits are subsystem-specific. They must not be added together as if one
budget controls the entire scorecard or repository process.

## Initial hot-path inventory

| Stage                               | Before / issue evidence                                                                                                | Current source-derived behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Peak additional space and status                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Project file discovery              | Prior `fast-glob` call materialized all returned names before enforcing `maxFiles`.                                    | `src/core/file-walker.ts` consumes `fg.stream`, stops after `maxFiles + 1`, then performs one bounded-concurrency metadata pass and sorts accepted records. Expected traversal is `O(F + path bytes + F log F)` including final ordering; Git index enumeration is separately capped at 64 MiB of command output.                                                                                                                                                                                                                                                                                                                                                                                                                               | Candidate paths, metadata results and ordering use `O(F + path bytes)`; glob internals and all call-site-specific repeat discovery still need a complete memory inventory. This local mitigation has focused tests, but repository-wide discovery reuse remains under review (#40/#56).                                                                                                                                             |
| Secret match locations              | Repeated prefix splitting cost `O(B × M)` and could become quadratic.                                                  | `src/core/secret-utils.ts` scans line starts once and advances a cursor across matches: `O(B + M + matched bytes)` for the match-location pass.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `O(lines + M + returned match bytes)` because locations and matches are materialized. 1k/10k comparison data is in `docs/BENCHMARKS.md`; broad matcher-count and maximum-byte coverage remains open (#40/#86).                                                                                                                                                                                                                      |
| Dependency graph summary            | Converging paths could enqueue the same vertex repeatedly before its first dequeue; queue records grew with edges.     | `src/core/dependency-tree.ts` marks vertices when enqueued. The summary traversal is expected `O(V + E)` and has a deterministic 131,072-edge regression asserting 768 unique enqueues and a vertex-bounded peak queue. Topological depth and cyclic shortest-distance fallback each scan reachable vertices and edges.                                                                                                                                                                                                                                                                                                                                                                                                                         | `O(V)` additional traversal state, excluding caller-owned `O(V + E)` adjacency; `buildDependencyTree` also builds an `O(V + E)` tree representation. Hash-based identity operations are expected-time. The high-fan-in regression is local only; whole ecosystem graph limits and scale coverage remain open (#40/#86).                                                                                                             |
| Task DAG scheduler                  | Prior scheduler used repeated ready-list sorting.                                                                      | `src/application/task-scheduler.ts` builds dependency/dependent indexes in expected `O(V + E)` and uses a deterministic binary min-heap, giving expected `O(V log V + E + W)` scheduling plus task work `W`. Concurrency is capped at 32.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `O(V + E + C + retained outcome bytes)` for graph indexes, queue, outcomes and active tasks. Large-task output-size bounds and complete invalidation-storm accounting remain open (#56).                                                                                                                                                                                                                                            |
| Immutable snapshots and cache       | Repeated discovery, content hashing, parsing, retention and eviction have cross-feature costs.                         | Snapshot reads and the shared analysis cache have explicit file/byte and entry/byte caps; the result cache is limited to 64 MiB total and 4 MiB per entry. Cold/warm 1k/10k/50k scorecard and a bounded invalidation soak are recorded in `docs/BENCHMARKS.md`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Snapshot, AST, analyzer result and serialized-output lifetimes are not yet audited together. Full cache churn, simultaneous scans and invalidation-storm peak space remain blockers (#40/#56/#86).                                                                                                                                                                                                                                  |
| AST compiler-host directory lookup  | `getDirectories` scanned every known source directory for each TypeScript resolver query: `O(L × Q)` candidate visits. | `src/analyzers/ast/source-analysis.ts` builds a parent-to-child directory index in expected `O(L)` time/space and serves each query with expected `O(1)` lookup plus returned children. A 512-directory cross-import test verifies resolution and importer digest invalidation. The synthetic 1k/10k/50k fixture records exact candidate/index visits and timings in `docs/BENCHMARKS.md`.                                                                                                                                                                                                                                                                                                                                                      | Additional index space is `O(L)`; queried child lists are returned as arrays to TypeScript. Hash-map lookup is expected-time. This correction addresses one resolver hot path; worker AST retention and whole-scan memory remain under audit (#39/#40/#56/#86).                                                                                                                                                                     |
| Lockfile/ecosystem resolution       | Repeated candidate filtering, context parsing and workspace matching can multiply package and declaration counts.      | Python workspace identities, Cargo lock candidates, Composer locked names and Cargo workspace file membership use one-pass indexes. Resolver marker contexts are parsed once per package and marker lookup is indexed. Go import/vendor ownership uses component tries instead of scanning all modules per import/file. Cargo member/exclude glob matching uses bounded dynamic programming with a shared 16M work-cell budget and explicit incomplete status on exhaustion. Exact pnpm name/version/peer resolution now uses indexes; Yarn's fallback is name-indexed and has a 250,000-candidate budget; ecosystem version matching and Cargo declaration joins each have a separate 250,000-candidate budget and explicit incomplete status. | The indexed joins and explicit candidate-work limits have focused regression coverage, including Cargo declaration-budget exhaustion. Remaining audit work includes parser/output materialization and cross-feature retention in `src/core/dependencies/ecosystem-inventory.ts` and `src/core/dependencies/lockfile-resolvers.ts`; add operation counters for every cap and dense-version/peer-variant cases (#40/#64/#79–#83/#86). |
| Provider clients                    | Unbounded requests/retries or responses would multiply CPU, latency and retained bytes.                                | Shared scan budgets cap provider concurrency at 32, request and whole-scan deadlines at 600,000 ms, retries at five, and retry delay at 60 seconds.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Per-provider response parsing, queued request count, decompression and retained result bytes still require a cross-client census. A timeout budget alone does not bound response size (#38/#48/#58/#67/#77/#89).                                                                                                                                                                                                                    |
| Stage A pre-execution gate          | Whole-tree scans, archive expansion and reference traversal could exceed runner resources.                             | `docs/MALICIOUS-CONTENT-AND-TRUST-GATE.md` documents the current scanner budgets: 100,000 files, 256 MiB text per tree, bounded graph/archive traversal, archive count/bytes and concurrency.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Scanner-specific buffers and exact two-tree/embedded-artifact peak accounting still need independent profiling. Non-npm artifact provenance, trusted bootstrap, host rules and static-analysis coverage remain blockers (#95/#96).                                                                                                                                                                                                  |
| Reports, history, vault and webhook | Output buffers, retained history, concurrent file state and unauthenticated network work can dominate resource use.    | History byte/record retention, vault serialization, webhook body/connection/header/time limits and several serializers have explicit caps.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | The combined live-space cost across scans, report generation, multiprocess state, artifact serialization and active webhook jobs has not been derived. Per-stage response/output caps and crash/cancellation resource counters remain audit work (#54/#65/#68/#84).                                                                                                                                                                 |

## AST import-graph digest traversal added on 2026-11-08

`transitiveImportDigests` in `src/analyzers/ast/source-analysis.ts` previously
used recursive Tarjan DFS. The implementation now uses explicit DFS frames,
visiting each graph vertex and edge once before stable sorting. Its full bound is
`O(V log V + E log E)` time and `O(V + E)` additional graph state; a deep chain
uses up to `O(V)` frames without consuming the JavaScript call stack. A
20,000-vertex chain regression asserts exactly 20,000 vertex visits, 19,999
edge visits and no more than 20,000 live frames. A cyclic fixture checks that
component digests are invariant under input order. This does not bound AST
retention or whole-scan memory.

The scope-tree builder still recurses over TypeScript nodes, so it now rejects
AST depth above 512 and total project AST nodes above 1,000,000 before later
recursive visitors execute. The project result is explicitly incomplete on
that error. A 600-level nested-source regression verifies the failure and the
existing 500-level taint-work-budget test remains intact. This limits accepted
analysis scope under pathological/deep source; it does not claim every deeply
nested valid program can be analyzed.

## Ecosystem index bounds added on 2026-11-08

For `P` locked package records, `W` workspace manifests, `G` Go module path
bytes, `Q` source import/file path bytes and `D` dependency declarations:

- Cargo lock candidates, Python workspace identities, Composer names and Cargo
  workspace membership are built in expected `O(P + W)` time and `O(P + W)`
  additional space, then queried with expected hash-map/set operations. This
  replaces repeated `O(P × W)` filtering in the covered joins. JavaScript hash
  tables do not provide a deterministic worst-case constant lookup guarantee.
- Resolver marker contexts are parsed once in `O(context bytes)` and indexed
  in expected linear time/space. Marker lookup avoids rescanning and reparsing
  same-name candidates. Ecosystem requirement predicates and Cargo workspace
  declaration joins each have a shared 250,000 candidate-work limit; exhaustion
  stops further linking and emits an incomplete warning. Their candidate-loop
  time is therefore `O(min(D × P, 250,000))` per respective resolver pass,
  plus `O(P + D + E)` index construction and output work. Candidate records and
  resulting edges remain materialized, requiring `O(P + E)` space.
- pnpm indexes instances by expected `O(P)` name/version/peer-context keys;
  resolution is expected `O(1)` per declaration and reports ambiguity when a
  version without a peer suffix maps to multiple instances. Yarn indexes each
  parsed descriptor by package name, avoiding full descriptor scans. Its
  fallback candidate checks are capped at 250,000 across the graph, after which
  resolution is explicitly incomplete. These bounds assume expected hash-map
  behavior and retain `O(P + E)` package/edge data.
- Go module and vendor ownership indexes are component tries built in
  `O(G)` time/space; import and source ownership queries are `O(path bytes)`
  each, for `O(G + Q)` total before parsing/import collection. This replaces
  sorting/scanning all modules per imported path or source file.
- Cargo workspace glob matching uses dynamic programming over pattern and
  candidate path lengths, with a shared 16,000,000-cell work cap. The matching
  pass is bounded by that cap; per-match live DP space is `O(pattern length +
path length)`. Exhaustion adds an explicit warning and makes inventory
  incomplete. The 128-manifest adversarial test checks that status transition.
- `graphSummary` now marks nodes reached at enqueue time. Its traversal is
  expected `O(V + E)` with `O(V)` queue/visited state, and a deterministic
  131,072-edge test measures unique enqueue count and peak queue occupancy.

These bounds describe the addressed operations only. Candidate exhaustion is
fail-closed, but ecosystem parser buffers, cross-feature snapshot retention,
and repository-wide memory accounting are not yet closed by this audit. The
isolated fixture-process benchmark at commit `41a3a9319b19bfb2c2290bafd1bb9fab794ddcd0`
is recorded in `docs/BENCHMARKS.md` and its JSONL artifact. That pre-optimization
50k scorecard warm process peak was 362 MiB heap and 1,394 MiB RSS. The latest
worktree run after AST indexing/bounds measured 299 MiB heap and 1,188 MiB RSS;
the peak remains material. Fixture isolation does not make cold/warm pass
memory incremental or prove a general bound.

## Measurements and phase gates

`docs/BENCHMARKS.md` and `docs/benchmarks/` contain Linux Node 24.22.1
synthetic 1k/10k/50k runs, including full-scorecard workloads, graph fixtures,
and an isolated-process run. The latest recorded 50k scorecard reported
complete fixture coverage, 50,003 files, 2.70 MB read and zero provider
requests; its warm process peak was 1,188 MiB RSS. These are one fixture and
machine, not a repository-wide memory proof, cross-platform result, or release
qualification. The legacy secret-location comparison intentionally stops at
10k because its prior algorithm is quadratic.

The new epic requires independent variation of file count and total bytes,
graph density, AST/rule counts and concurrency; p50/p95 wall time, files/s,
MiB/s, CPU, peak RSS/heap, I/O, cache/queue pressure, coverage and planted
finding accuracy; and exact baseline/artifact identity. The dedicated 100k and
250k campaign must wait until combined Batches 07–16 are accepted and merged.
1M/2M qualification and bounded 5M/10M stress attempts belong to final release
qualification, not this batch.

## Open work before sign-off

- Complete the source inventory for every material analyzer, parser, resolver,
  serializer, provider, integration, state store and Git/history path across
  prior and combined batches. Record before/after time and peak-space bounds,
  input limits, queue/cache lifetime and source/test references.
- Finish operation counters for candidate/workspace caps, then audit ecosystem
  parser and output materialization without converting ambiguous packages to
  exact identities. Add dense-version, peer-variant and large-workspace
  resource fixtures.
- Profile full scan cold/warm/incremental paths and multiple simultaneous
  scans; vary bytes independently from file count and include huge reports,
  dense graphs, deep imports, high-degree edges and cache churn.
- Add cross-platform evidence and compare the exact frozen v2.2.1 baseline and
  task-matched tools where behavior overlaps; derive performance thresholds
  from pilots rather than inventing budgets.
- Update this document with verified/fixed/retested classifications, raw run
  links and honest limits. Do not mark #40/#56/#86 complete until all their
  acceptance and required phase gates are met.
