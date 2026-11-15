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
| `N`      | TypeScript syntax-tree nodes traversed                                     |
| `S`      | AST symbols and references                                                 |
| `A`, `W` | pending local aliases and assignment-write events                          |
| `U`      | distinct identifiers with one or more assignment writes                    |
| `M`      | secret matches                                                             |
| `R`      | findings and serialized report bytes, as applicable                        |
| `K`      | configured built-in and custom rules evaluated                             |
| `C`      | bounded concurrent workers or provider requests                            |
| `P`      | provider requests including retries                                        |
| `H`      | history records or commits                                                 |
| `D`      | maximum input or graph depth                                               |
| `L`, `Q` | unique source directories and TypeScript directory queries                 |

The limits are subsystem-specific. They must not be added together as if one
budget controls the entire scorecard or repository process.

## Initial hot-path inventory

| Stage                                        | Before / issue evidence                                                                                                                                                                   | Current source-derived behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Peak additional space and status                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Project file discovery and reads             | Prior `fast-glob` call materialized all returned names before enforcing `maxFiles`; concurrent reader calls could open one handle per candidate.                                          | `src/core/file-walker.ts` consumes `fg.stream`, stops after `maxFiles + 1`, then performs one bounded-concurrency metadata pass and sorts accepted records. `TextFileReader` reserves file/byte budgets across callers and limits active reads to 8 by default (hard maximum 32); cancellation removes queued work and closes active handles. Expected traversal is `O(F + path bytes + F log F)` including final ordering; Git index enumeration is separately capped at 64 MiB of command output.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Candidate paths, metadata results and ordering use `O(F + path bytes)`; read buffers are bounded by the aggregate byte budget and active I/O concurrency, with queued requests counted against the file budget. Snapshot capture reuses a frozen discovery list and prior content only when canonical file identity and metadata match; cross-feature retention remains under the broader audit (#40/#56).                                                                                                                                                                                                                                                                                                                                                                       |
| Secret match locations                       | Repeated prefix splitting cost `O(B × M)` and could become quadratic.                                                                                                                     | `src/core/secret-utils.ts` scans line starts once and advances a cursor across matches: `O(B + M + matched bytes)` for the match-location pass.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `O(lines + M + returned match bytes)` because locations and matches are materialized. 1k/10k comparison data is in `docs/BENCHMARKS.md`; broad matcher-count and maximum-byte coverage remains open (#40/#86).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Dependency graph summary                     | Converging paths could enqueue the same vertex repeatedly before its first dequeue; queue records grew with edges.                                                                        | `src/core/dependency-tree.ts` marks vertices when enqueued. The summary traversal is expected `O(V + E)` and has a deterministic 131,072-edge regression asserting 768 unique enqueues and a vertex-bounded peak queue. Topological depth and cyclic shortest-distance fallback each scan reachable vertices and edges.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `O(V)` additional traversal state, excluding caller-owned `O(V + E)` adjacency; `buildDependencyTree` also builds an `O(V + E)` tree representation. Hash-based identity operations are expected-time. The high-fan-in regression is local only; whole ecosystem graph limits and scale coverage remain open (#40/#86).                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Task DAG scheduler                           | Prior scheduler used repeated ready-list sorting.                                                                                                                                         | `src/application/task-scheduler.ts` builds indexes in expected `O(V + E)` and uses a binary min-heap: graph traversal is `O(V + E)`, queue operations are `O(V log V)`, plus task work `W`. Hard caps are `V ≤ 100,000`, raw dependency entries `≤ 1,000,000`, ID/dependency metadata `≤ 16 MiB`, task ID `≤ 1 KiB`, and active tasks `C ≤ 32`; explicit versions/fingerprints have a separate 16 MiB cap. Cancellation marks queued work terminal, signals active tasks, waits for cleanup, and removes its listener.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Graph/index space is `O(V + E)` under those caps; execution also retains `O(V + E + C + R)` for outcomes, queue, active tasks and caller-visible output bytes `R`. `R` remains output-contract/caller-owned and is not hidden by the cache cap. Cache serialization defaults to 10,000 entries (hard maximum 100,000), 64 MiB total key+payload, and 4 MiB per entry. Stress tests cover fan-out, converging graphs, a 10,000-node chain, invalidation storms, cancellation, malformed budgets and oversized output. This bounds retained cache state, not complete process RSS (#56/#40).                                                                                                                                                                                       |
| Immutable snapshots and cache                | Repeated discovery, content hashing, parsing, retention and eviction have cross-feature costs.                                                                                            | One frozen `ScannerContext` and `ProjectSnapshot` are passed to the scorecard, Doctor, dependency resolvers and analyzers. Snapshot capture shares discovery and bounded reads; previous snapshots reuse only matching canonical path/file identities and content digests. AST chunks key stable path/content/import-component/transitive-dependency fingerprints; the incremental DAG keys explicit task inputs and dependency output digests so an unchanged output does not invalidate its dependents. Cache values are size-estimated before V8 serialization; outputs exceeding a 2× per-entry transient estimate or with unsupported/accessor shapes skip caching and do not produce a reusable digest. Cold, warm, one-file incremental and simultaneous scorecard reads/cache/wall/heap/RSS results are recorded with raw JSONL in `docs/BENCHMARKS.md`.                                                                                                                                        | For `F` files, `B` captured bytes, `P` path bytes and `D` dependency digests, snapshot ordering/hash/reuse is `O(F log F + B + P + D)` time and `O(F + B + P + D)` retained state within file/byte budgets. Digest sorting uses `O(F)` temporary references. Output preflight enumerates array and plain-object properties incrementally and stops when the estimate exceeds budget; work is bounded by the estimate limit plus the length of a property key inspected at the cutoff. Cache churn and concurrent scans are tested, but transient compiler/runtime allocations and caller-visible `R` still contribute to observed peak RSS; retained-byte metrics cover only serialized cache buffers and keys, not V8 container overhead or total process memory (#40/#56/#86). |
| AST compiler-host directory lookup           | `getDirectories` scanned every known source directory for each TypeScript resolver query: `O(L × Q)` candidate visits.                                                                    | `src/analyzers/ast/source-analysis.ts` builds a parent-to-child directory index in expected `O(L)` time/space and serves each query with expected `O(1)` lookup plus returned children. A 512-directory cross-import test verifies resolution and importer digest invalidation. The synthetic 1k/10k/50k fixture records exact candidate/index visits and timings in `docs/BENCHMARKS.md`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Additional index space is `O(L)`; queried child lists are returned as arrays to TypeScript. Hash-map lookup is expected-time. This correction addresses one resolver hot path; worker AST retention and whole-scan memory remain under audit (#39/#40/#56/#86).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Reachability TypeScript module resolver      | Resolver `readFile` delegated to `ts.sys.readFile` after path containment, with no per-file size or opened-handle stability check.                                                        | The root-bound resolver opens the canonical in-root file once, rejects non-regular or over-1 MiB inputs, reads only the opened size, checks for growth and revalidates file identity/path before returning text. For each `Q` metadata reads and bytes `Bᵣ`, work is `O(Q + Bᵣ)` and the largest transient buffer is 1 MiB; rejected paths remain unresolved and coverage is reported by the caller.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | The resolver continues to rely on TypeScript for candidate enumeration but no longer materializes arbitrarily large package metadata. Cross-platform integration coverage remains part of the checkpoint verification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Filesystem check/use path matching           | Textually different immutable aliases could hide a check followed by reopening the same path.                                                                                             | The concurrency analyzer indexes unique local declarations by name once per function, then follows only visible `const` aliases with a 16-hop cap. Duplicate declaration names stay unresolved; mutable declarations and non-visible aliases are not followed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | For `C` calls and `D` declarations in a function, indexing is `O(D)` and path matching is expected `O(C × (A + H))`, where `A` is AST ancestor depth and `H ≤ 16` is alias hops; temporary state is `O(D + A)` beyond existing call/declaration facts. The finding remains a same-function heuristic and does not prove canonical containment or eliminate symlink/provider races (#60).                                                                                                                                                                                                                                                                                                                                                                                         |
| Lockfile/ecosystem resolution                | Repeated candidate filtering, context parsing and workspace matching can multiply package and declaration counts.                                                                         | Python workspace identities, Cargo lock candidates, Composer locked names and Cargo workspace file membership use one-pass indexes. Cargo crate names/semantic versions and Composer package/requirement identities are validated in linear time in captured text; custom Composer origin classification scans the root repository list once and withholds unknown origins from public OSV. Resolver marker contexts are parsed once per package and marker lookup is indexed. Go import/vendor ownership uses component tries instead of scanning all modules per import/file. Cargo member/exclude glob matching uses bounded dynamic programming with a shared 16M work-cell budget and explicit incomplete status on exhaustion. Exact pnpm name/version/peer resolution now uses indexes; Yarn's fallback is name-indexed and has a 250,000-candidate budget; ecosystem version matching and Cargo declaration joins each have a separate 250,000-candidate budget and explicit incomplete status. | The indexed joins and explicit candidate-work limits have focused regression coverage, including Cargo declaration-budget exhaustion. Remaining audit work includes parser/output materialization and cross-feature retention in `src/core/dependencies/ecosystem-inventory.ts` and `src/core/dependencies/lockfile-resolvers.ts`; add operation counters for every cap and dense-version/peer-variant cases (#40/#64/#79–#83/#86).                                                                                                                                                                                                                                                                                                                                              |
| Provider clients                             | Unbounded requests/retries or responses would multiply CPU, latency and retained bytes.                                                                                                   | Shared scan budgets cap concurrency at 32, per-request/whole-scan deadlines at 600,000 ms, retries at five, and retry delay at 60 seconds. Response caps include OSV 16 MiB per batch plus 64 MiB aggregate/query call; deps.dev 1 MiB per response plus 32 MiB default/64 MiB hard serialized cache cap; npm health 8 MiB per packument and bounded version/history extraction; provenance 8 MiB metadata and 32 MiB artifact; exploit intelligence 4 MiB response and 200 CVEs. Dependency-confusion checks at most 5,000 names.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Per-response buffers are bounded by the client caps and concurrency; OSV retained response content is additionally capped at 64 MiB per call. Parsed object overhead is proportional to accepted bytes but runtime object-size constants are not promised. Provider request count still depends on the eligible inventory and scan deadline; queued input/result structures are covered by their analyzer rows.                                                                                                                                                                                                                                                                                                                                                                  |
| Dependency-confusion manifest and lookups    | The analyzer read the root manifest without a byte limit and materialized all dependency records before filtering; provider work was bounded only by concurrency.                         | `TextFileReader` now reads one race-checked manifest of at most 2 MiB. Candidate discovery scans own entries once, rejects names over 214 UTF-8 bytes and requirements over 16 KiB, retains at most 5,000 requests and reports every withheld candidate as partial. For manifest bytes `B` and dependency entries `J`, time is `O(B + J + P)` plus provider latency; peak additional space is `O(B + 5,000 + C + R)`, where `P ≤ 5,000`, `C ≤ 32`, and findings `R ≤ P`. JSON object-property and hash behavior is runtime-dependent; no hash worst-case guarantee is claimed.                                                                                                                                                                                                                                                                                                                                                                                                                          | Regressions cover the 2 MiB read ceiling, exact 5,000 request cap, overlong identity rejection, truthful skipped count, and the existing concurrency bound.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Installed lifecycle manifest analysis        | Every resolved install path was checked and each package manifest was read without a byte or aggregate budget; per-package warnings and findings could also grow with the full inventory. | Lockfile work remains bounded by its resolver caps. Installed manifests use one reader with `F ≤ 20,000`, `B ≤ 32 MiB`, and `1 MiB` per file. At most 10,000 findings and five warning examples are retained; all other matches/skips are counted and make coverage partial. With `V` resolved identities, manifest bytes `B`, and at most five rules across three lifecycle keys, processing is `O(V + B + 15F)` plus JSON/regex parsing; peak additional space is `O(V + Bmax + R + 1)`, where `Bmax ≤ 1 MiB` is one read buffer and `R ≤ 10,000`.                                                                                                                                                                                                                                                                                                                                                                                                                                                    | New adversarial coverage checks an oversized installed manifest is skipped and never reported clean. Read races, symlinks, and root containment are enforced by `TextFileReader`; unverified optional/missing installs remain partial.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| SBOM root manifest                           | Direct `generateSbom` callers read `package.json` without a size limit, and captured-source callers trusted any manifest length.                                                          | Live reads use the existing opened-handle identity check with a 2 MiB cap; captured inputs are byte-counted before parsing. Parsing takes `O(B)` input time and space for `B ≤ 2 MiB`; downstream SBOM graph/output space remains separately bounded by inventory and serializer caps.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | New tests cover both live and captured over-limit input. The larger SBOM serialization/attestation output dimensions remain in the report/provider census.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Toolip config and ignore inputs              | Startup configuration and `.toolipignore` were read with unbounded `readFile` calls before the scanner's normal file budgets applied.                                                     | Both use race-checked `TextFileReader` inputs capped at 1 MiB. Config read failures are explicit; an unreadable ignore file falls back to the built-in ignore set, which scans more files rather than silently omitting them. Time/space are `O(B)` for `B ≤ 1 MiB` plus retained ignore lines.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Oversized-config and oversized-ignore regressions cover the input caps and failure/fallback behavior.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Dependency warning correlation               | Every graph warning scanned every unresolved package name using substring search, taking `O(W·U)` string checks in dense malformed graphs.                                                | Generated unresolved-edge warnings carry a stable manager/prefix and package identity. A name set plus one bounded warning parse now correlates in expected `O(U + W + Z)` time/space, where `Z` is total warning bytes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | A scoped-package regression verifies warning-to-edge deduplication remains exact. Set lookup is expected-time; only resolver-generated warning formats are classified as edge duplicates.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| User and tool generated file reads           | Several CLI, hook, snapshot and generated Go checksum paths checked metadata before `readFile`, leaving growth races that could allocate beyond their nominal cap.                        | `src/core/bounded-file.ts` opens a regular non-symlink file, checks descriptor/path identity, reads at most `limit + 1` bytes, and verifies size and timestamps after reading. VEX inputs cap at 16 MiB; advisory snapshots at 64 MiB; user hooks at 1 MiB; local lock owner markers at 256 bytes; generated Go checksum files share a 32 MiB aggregate cap. Oversized hooks fail before replacement, preserving the user's original hook.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | For an input cap `X`, read time is `O(min(B, X) + 1)` and transient bytes are at most `X + 1`; UTF-8 decoding adds at most `O(X)` output space. Generated Go sums use aggregate `X ≤ 32 MiB`. `tests/core/bounded-file.test.ts` covers the exact cap and invalid UTF-8; hook regression checks oversized user state is unchanged. These are per-input/stage limits and do not sum to a process-wide RSS bound.                                                                                                                                                                                                                                                                                                                                                                   |
| Advisory snapshot parsing and pending cache  | `Object.keys(records)` and `Object.entries(records)` copied untrusted keys before the 200,000-record cap; pending cache records had no aggregate serialized-byte budget.                  | `src/providers/intelligence/snapshot-cache.ts` counts own record properties and validates each in place, stopping at record 200,001; flush merges without an `Object.entries` copy. Persisted snapshots cap at 64 MiB/200,000 records; one pending value caps at 16 MiB and pending serialized values plus keys cap at 64 MiB. Canonical hashing uses a generator with maximum depth 256, one million nodes and a 64 MiB output cap.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Parse time is `O(B + min(R, 200,001))` plus JSON parsing and validation; additional validation state is `O(1)` beyond the parsed object. Pending serialized retention is `≤64 MiB` with `≤200,000` entries; base parsed state is backed by a `≤64 MiB` file. Flush still requires `O(R log R)` deterministic ordering and `O(R + B)` map/output materialization. Runtime object overhead and concurrent cache reads remain part of the cross-feature live-space audit.                                                                                                                                                                                                                                                                                                           |
| Filesystem watch tree and event queue        | Non-Linux fallback recursively registered one watcher per directory with recursive JavaScript calls and no application-level directory cap.                                               | `src/core/watch/watch.ts` now discovers fallback directories iteratively, caps active watches at 50,000 (caller may lower the cap), and reports when coverage is incomplete. Per-directory reconciliation events coalesce in a set bounded by active watched directories; scan scheduling holds at most one active scan and one queued follow-up. Linux uses one native recursive watcher.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Fallback traversal is `O(D + entries)` time and `O(min(D, 50,000))` watcher/queue state for directory count `D`; call-stack use is `O(1)`. Native kernel watcher resource use is platform-managed and not represented by JavaScript heap bounds. A non-Linux cap regression is added in `tests/core/watch.test.ts`.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Stage A pre-execution gate                   | Whole-tree scans, archive expansion and reference traversal could exceed runner resources.                                                                                                | `docs/MALICIOUS-CONTENT-AND-TRUST-GATE.md` documents the current scanner budgets: 100,000 files, 256 MiB text per tree, bounded graph/archive traversal, archive count/bytes and concurrency.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Scanner-specific buffers and exact two-tree/embedded-artifact peak accounting still need independent profiling. Non-npm artifact provenance, trusted bootstrap, host rules and static-analysis coverage remain blockers (#95/#96).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| JSON, SARIF, Markdown and HTML report output | `JSON.stringify` and markdown rendering materialized full reports without an output or traversal limit.                                                                                   | `src/core/report-writer.ts` supplies a shared bounded JSON serializer to report, SARIF, scorecard, policy, PR-scan, vulnerability, SBOM, VEX, history and high-volume CLI JSON outputs; generated npm attestations use a 16 MiB artifact-specific ceiling. `src/core/history/report.ts` also caps Markdown/HTML with a 64 MiB ceiling, depth 256, one million nodes and one million fragments. Markdown uses the same bounded report preflight and rejects rendered output above 64 MiB. Report JSON is compact and preserves source property order; unsupported accessors, cycles and BigInt values fail explicitly.                                                                                                                                                                                                                                                                                                                                                                                   | Traversal is `O(R + output bytes)`; serializer chunks are limited to 64 MiB output, one million fragments and one million nodes, and the returned string adds up to another 64 MiB during final joining. An oversized escaped string is rejected by a linear byte-count pass before allocating its escaped copy. Markdown can transiently retain the bounded preflight JSON and rendered Markdown together; exact V8 object overhead is not included.                                                                                                                                                                                                                                                                                                                            |
| Reports, history, vault and webhook          | Unbounded report output, retained history, webhook queues and simultaneous scans can dominate live space.                                                                                 | History accepts `H ≤ 5,000` entries and `Bₕ ≤ 32 MiB`; vault plaintext is `≤47 MiB`, encrypted file `≤64 MiB`, and secrets `≤100,000`. Signed artifact capture is `≤20,000` files, `≤4 MiB` each (`package.json ≤256 KiB`), and `≤64 MiB` total. MCP output is at most 16 MiB, one million nodes, and 100,000 fragments. GitHub App webhooks cap each body at 1 MiB, headers at 100, connections at 128, queue at 1,000 (default 64), active scans at 16 (default 2), and delivery state at 16 MiB / 100,000 deliveries / 10,000 installations; snapshots cap at 20,000 files, 16 MiB tree output and 64 MiB blobs.                                                                                                                                                                                                                                                                                                                                                                                     | Each individual history/vault/report/MCP/webhook stage has bounded inputs/outputs. HTTP can still retain up to 128 MiB of raw request bodies before parsing, and up to 16 active GitHub App scans can each retain their own snapshot and analyzer working state. The concurrent peak-space model and its remaining RSS/platform measurement limits are recorded below (#40/#56/#65/#68/#84).                                                                                                                                                                                                                                                                                                                                                                                     |

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

- npm lockfile validation and graph construction now iterate object properties
  directly instead of allocating repeated `Object.entries` tuples and temporary
  per-package dependency arrays. Package records and total declarations each
  cap at 1,000,000. An install-path parent/name index resolves dependencies in
  expected `O(B + P + D + E)` time and `O(P + E)` retained state, with at most 256
  ancestor hops per declaration; deeper unresolved lookup fails explicitly.
  The bounds include index construction and assume expected hash-map behavior.
- pnpm package/snapshot maps and Yarn lock entries also use direct iteration;
  dependency-section parsing yields one edge at a time, and graph declarations
  cap at 1,000,000 before retaining more edge specifications. Workspace pattern
  discovery stops at 256 patterns, workspace manifests cap at 10,000 per lock
  file and 32 MiB aggregate text, and streamed directory discovery stops at
  10,000 results. Lock text itself is bounded by the shared dependency reader.
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
- Offline Go checksum parsing scans `go.sum` in `O(Bg)` time for `Bg` bytes
  and retains `O(P)` exact module/version checksum entries. Malformed nonblank
  records and invalid hashes now produce explicit incomplete-coverage warnings;
  archive checksums remain distinct from `/go.mod` checksums.
- Go workspace directive parsing is a single `O(L)` pass over `L` lines with
  `O(U)` storage for distinct `use` members and one current-line slice; it
  scans incrementally instead of materializing a line array. It stops after
  100,000 lines and reports malformed members, unclosed blocks, invalid
  version/toolchain directives and unknown directives as incomplete coverage.
- Cargo workspace glob matching uses dynamic programming over pattern and
  candidate path lengths, with a shared 16,000,000-cell work cap. The matching
  pass is bounded by that cap; per-match live DP space is `O(pattern length +
path length)`. Exhaustion adds an explicit warning and makes inventory
  incomplete. The 128-manifest adversarial test checks that status transition.
- Cargo lock graph import parses `L` bounded lock bytes into `P` package records
  and `E` dependency edges, then uses indexed package identities and bounded
  declaration matching. The parser's expected work is `O(L + P + E + W)` plus
  at most 250,000 candidate checks for Cargo workspace declaration joins;
  retained parsed packages and edges are `O(P + E)`, in addition to bounded
  input text and TOML parse state. A generated 50k registry-package chain
  parsed 50,001 vertices and edges in 1.78 s with a 575 MiB sampled RSS peak.
  This is a single parser-scale sample; Cargo feature activation for registry
  packages absent from the captured workspace remains explicitly unknown.
- `graphSummary` now marks nodes reached at enqueue time. Its traversal is
  expected `O(V + E)` with `O(V)` queue/visited state, and a deterministic
  131,072-edge test measures unique enqueue count and peak queue occupancy.
- Dependency graph digests preserve the canonical JSON byte format while
  streaming the top-level hash instead of normalizing and joining a second
  complete graph copy. Per-record canonical strings are sorted for stable
  ordering; total serialized input is capped at 64 MiB and two million graph
  records, with `O(Bg log(P + E) + P + E)` worst-case time and
  `O(Bg + P + E)` temporary/retained
  state, where `Bg` is canonical graph bytes. A 50k-node/100k-edge regression
  covers graphs beyond the generic canonical JSON node limit.

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
and an isolated-process run. The latest 50k scorecard reported complete
fixture coverage, 50,003 files, 2.70 MB read, zero provider requests and
3,125/3,125 warm AST chunk hits; its warm process peak was 1,117 MiB RSS.
Repeated 50k runs ranged from 1,116 to 1,143 MiB RSS, so the observed memory
change is variable. These are one fixture and machine, not a repository-wide
memory proof, cross-platform result, or release qualification. The legacy
secret-location comparison intentionally stops at 10k because its prior
algorithm is quadratic.

The scale harness now exposes independent controls for file count, requested
source-byte target, exported symbols, up to eight planted AST rule IDs, seeded
files, simultaneous scorecards and graph fanout. It records exact fixture
hashes, planted-finding counts, coverage, CPU, heap/RSS samples and cache
counters. A small 4-file/two-scorecard and 20-node/fanout-four smoke is preserved
in `docs/benchmarks/toolip-v3.2.1-batch09-harness-smoke-2026-11-09-linux-node24.jsonl`.
The scorecard API does not stream findings, so time-to-first-finding remains
unavailable; simultaneous scorecards do not vary the internal AST worker pool.
The smoke does not complete the independent 1k/10k/50k dimensional campaign or
provide p50/p95. Whole-codebase CPU/RSS/input-I/O profiles, queue pressure,
cross-platform runs and measured budgets remain open. The dedicated 100k and
250k campaign must wait until combined Batches 07–16 are accepted and merged.
1M/2M qualification and bounded 5M/10M stress attempts belong to final release
qualification, not this batch.

## Signed WASM validation isolation

For a signed analyzer plugin, manifest and module reads are capped at 64 KiB
and 8 MiB. Digesting and linear memory-section validation take `O(Bm)` time
and `O(1)` additional parser space for module bytes `Bm`; compilation, import
enumeration and ABI export inspection run in a terminating worker with a
10-second deadline and 32 MiB V8 old-generation limit. Worker message transfer
may temporarily retain another `O(Bm)` byte copy. Node's worker resource limit
is not an OS-level memory or CPU limit, so platform behavior and process-wide
resource accounting remain open. Runtime execution has its own signed
input/output/memory/time caps and terminable worker. This is isolation from
event-loop blocking and ambient host APIs, not a claim that arbitrary native
code is sandboxed.

## Batch 12 Dockerfile stage metadata (2026-11-12)

For a Dockerfile of `B` bytes, `I` normalized instructions and `S` stages, the
previous implementation selected the final stage and repeatedly filtered its
instructions in `O(I)` time, with `O(I)` retained instruction/line references.
It did not model stage inheritance. The current bounded physical-line and
heredoc pass, indexed stage-alias graph, and forward metadata propagation use
`O(B + I + S)` time and `O(B + I + S)` additional space. The space bound
includes the physical-line view, normalized instruction text, heredoc shell
body copy, stage/instruction references, expected-time alias maps and sets,
metadata states, warnings and findings. Each instruction is assigned to one
stage and examined a constant number of times; map/set operations are
expected/amortized, not deterministic worst-case. Input byte/file budgets come
from the shared scanner and text reader. No new performance campaign was run:
this correctness change does not target the benchmarked AST path.

Stage state follows only captured named or numeric prior-stage references.
External image configuration, UID lookup for named users, and `ONBUILD`
effects are unresolved inputs, so affected coverage remains partial. Focused
tests cover inheritance/overrides, scratch defaults, external metadata,
unknown usernames, malformed references, secrets, remote ADD and heredocs;
these tests are not release verification.

## Open work before sign-off

### Concurrent-service peak-space model

The service combines bounded request admission with bounded scan and artifact
stages. For one process, model retained service data as
`O(C_http × B_request + Q × B_queue_entry + C_scan × S_scan + B_delivery +
B_cache + B_output)`, where `C_http ≤ 128`, `B_request ≤ 1 MiB`,
`Q ≤ 1,000`, and `C_scan ≤ 16` (default 2). `S_scan` includes each scan's
captured snapshot, dependency and AST graphs, findings and serialization
buffers; its source-specific dimensions and caps are listed above. Delivery
state, caches and output have separate fixed caps. Independent CLI processes
add their own per-process terms. This model accounts for overlap and explicit
admission limits; it does not convert V8 object graphs, worker/native
allocations or OS watcher state into an exact byte ceiling. The current
1,117 MiB observed warm 50k scorecard RSS is evidence for one fixture, not a
hard process-memory limit. Peak RSS under simultaneous service scans and
platform-specific filesystem watcher resources still require measurement.

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

## Secret-location maximum-size/match-count check (2026-11-14)

`findSecretMatches` computes line starts once and advances a monotonic line
cursor while matches arrive in source order. The location pass is `O(B + M)`
time after regex matching, plus the regex engine and SHA-256 work proportional
to matched bytes; retained results and line starts are `O(M + lines)`. A new
regression exercises 50,000 matches in a 2 MiB string and checks first,
middle, and last positions. Isolated measurements are in
`docs/benchmarks/toolip-v3.2.1-secret-locations-2026-11-14-linux-node24.jsonl`:
the optimized path measured 1.56 ms at 1k lines/200 matches, 8.94 ms at 10k/
2k, and 38.52 ms at 50k/10k; the legacy baseline measured 12.58 ms and
396.57 ms for 1k and 10k, with identical location checksums. The legacy 50k
case is capped/skipped due to its quadratic prefix splitting. These are single
process-local samples, not a bound on regex matching or a stable CI threshold.
The rest of the repository-wide source census and cross-feature peak-memory
accounting remain open.

## AST project reuse memory change (2026-11-08)

`Security Doctor` now reuses AST findings and dependency digests for an
identical immutable source project. Project digest construction sorts the
eligible paths and hashes each path/content digest incrementally, using
`O(F log F)` time for path ordering and `O(F)` references for the ordered
source list, instead of allocating a second tuple list plus a full JSON
serialization. Chunking and lookup are `O(F)` time and space. Warm reuse
deserializes cache chunks in `O(C)` time and temporary space where `C` is the
serialized AST result size; serialized cache retention is capped by the
existing 64 MiB aggregate and 4 MiB per-entry limits. Any missing/invalid
chunk falls back to the worker, preserving correctness. The cache adds up to
the existing bounded cache capacity, so it does not establish a low total
process-memory ceiling.

Cold AST construction still runs in the worker with project source text,
TypeScript nodes, scopes, graph indexes and per-file findings live together;
its space remains proportional to input bytes plus AST nodes, import graph
and findings (`O(B + N + V + E + R)`). A 50k Linux Node 24.22.1 synthetic
scorecard measured 18.87 s cold and 2.39 s warm with complete coverage. Warm
reuse hit all 3,125 AST chunks. One sample measured 1,116 MiB process RSS and
423 MiB heap, compared with the preceding sample's 1,188 MiB RSS and 299 MiB
heap; a repeat measured 1,143 MiB RSS and 440 MiB heap. The variability and
heap increase mean this is evidence that warm AST rebuilding is avoided, not a
stable memory guarantee. Raw rows are in
`docs/benchmarks/toolip-v3.2.1-ast-cache-memory-50k-linux-node24.jsonl`.
Cold AST-worker RSS remains above 1 GiB and is still an open memory review
item. The refreshed full 1k/10k/50k run measured 423/612/1,099 MiB cold RSS
and 398/596/1,117 MiB warm RSS, with AST chunk hits at every warm size. This
newer sample agrees with faster warm reuse, while repeated 50k runs ranged
from 1,116 to 1,143 MiB RSS and 307 to 440 MiB heap. The full codebase
peak-space inventory and multi-scan/concurrency profile remain open; all
related issues remain Partial. The full 36-row artifact is
`docs/benchmarks/toolip-v3.2.1-isolated-ast-cache-2026-11-08-linux-node24.jsonl`.

### AST chunk completeness validation (2026-11-08)

For `C` cached paths in one chunk, cache validation now checks exact path order,
one unique dependency digest per path, and each 64-character lowercase SHA-256
value. This validation is `O(C)` time and `O(C)` temporary set space, bounded
by the existing entry-size/cache limits. Any malformed, truncated or duplicate
digest set causes the AST worker to recompute the result. Regression fixtures
exercise those corruptions, cache eviction and findings equivalence. This
validation does not reduce the cold AST worker's source/AST duplication or
establish an aggregate peak bound across simultaneous scans.

### Maven text tree parsing (2026-11-08)

For `B` bytes of captured Maven dependency-tree output and `D` maximum tree
depth, line scanning and coordinate validation are `O(B)` time; the current
text split retains `O(B)` line storage, and package/edge records retain
`O(V + E)` space. Stack-based parent lookup is `O(1)` per accepted row with
`O(D)` parent slots. Only documented five-field and six-field coordinates,
recognized scopes/annotations and three-column indentation are accepted;
unsupported or malformed layouts mark the inventory incomplete. Instance
paths include artifact type/classifier at every depth, while ambiguous edges
remain unresolved rather than being guessed. This addresses the specific #82
parser defect, not real Maven export compatibility, BOM/property resolution,
or Java provider acceptance.

### AST component-aware cache invalidation (2026-11-08)

The AST cache now separates stable cache-chunk identity from analyzed content.
For `F` files and `E` resolved local imports, the worker parses each source to
resolve module edges, indexes source directories, and traverses weak components
in `O(F + E)` graph time after resolver work. Directory indexing/resolution is
`O(FP + ER)` as described above. Per-component fingerprints hash each member's
path and content; transitive dependency digests also invalidate importers when
a dependency changes. A changed component causes fresh AST analysis for the
whole weak component, conservatively including any source that can share its
TypeScript Program. Unrelated component chunks remain reusable. Script files,
declarations and global module declarations force the existing project-wide
fallback, because those files can change checker semantics without import edges.

The cache read is `O(F)` in path/fingerprint validation plus finding payload
size, using at most one bounded cache entry at a time; writes remain limited by
the shared 64 MiB cache and 4 MiB entry caps. Planning and analysis run in
separate killable workers with 1 GiB old-generation, 128 MiB young-generation
and 16 MiB stack limits, so cache planning adds worker startup and transient
source transfer. The analysis worker independently recomputes its plan and its
per-file dependency digests are compared with the cache plan before results are
accepted. Malformed plan/cache data fails closed to a fresh analysis or an
incomplete AST result.

The synthetic scorecard incremental run changed one independent source file.
On Linux Node 24.22.1 it reused 62/63 chunks at 1k, 624/625 at 10k and
3,124/3,125 at 50k; the prior implementation reused none. At 50k, cold/warm/
incremental wall times were 20.51/4.52/4.57 seconds; the process sampled peak
RSS was 932/1,031/1,210 MiB. The latter is a process-level peak after cache
retention across passes, not the incremental operation's isolated allocation.
Raw rows: `docs/benchmarks/toolip-v3.2.1-ast-cache-invalidation-2026-11-08-linux-node24.jsonl`.
Only one sample per size is available; these results do not establish p50/p95,
release qualification or lower peak memory. Full concurrent-scan profiling and
the broader #40/#56/#86 acceptance remain open.

### Two concurrent 50k scorecards (2026-11-08)

The isolated concurrent fixture executes two offline scorecards over one shared
immutable 50k source snapshot, each with an independent result cache. Both
completed with full coverage and zero provider requests in 11.73 seconds. The
process sampled peak RSS was 1,366 MiB and heap was 477 MiB, compared with
932 MiB RSS on the single-pass cold 50k run in this benchmark family. This
measures one process and one input shape; it is not a hard memory ceiling. The
AST plan is currently cloned into a bounded worker and changed components are
then sent to an analysis worker, so reducing source transfer/worker duplication
is a candidate for further profiling rather than a proven fix. Raw data:
`docs/benchmarks/toolip-v3.2.1-concurrent-memory-50k-linux-node24.jsonl`.

### No-cache AST worker path (2026-11-08)

When a caller supplies no `AnalysisResultCache`, `runSecurityDoctor` no longer
builds a component cache plan and then transfers the same full source set to a
second worker. It performs one bounded AST analysis worker call; that worker
already builds the component plan as part of analysis and returns the required
per-file dependency digests. Cache metrics still report the number of AST
chunks that would have missed (`ceil(F / 16)`). Cache-enabled calls keep the
separate planning pass because they need component fingerprints before deciding
which chunks/components to analyze. This removes one worker startup and one
full-source structured clone for uncached runs, without changing the analysis
result.

One-shot Linux Node 24.22.1 uncached synthetic scorecards measured 1.03/4.12/
17.29 s and 356/584/835 MiB process RSS at 1k/10k/50k. These samples do not
compare directly with the cache-enabled cold fixture and do not quantify an
isolated before/after saving. Raw rows are in
`docs/benchmarks/toolip-v3.2.1-no-cache-scorecard-2026-11-08-linux-node24.jsonl`.

### Cache-enabled cold AST worker path (2026-11-08)

On an empty cache, the AST analysis worker now returns component digests along
with findings and dependency digests. Security Doctor can therefore seed cache
chunks directly without first cloning all source inputs into a separate plan
worker. This reduces one worker startup and one full-source structured-clone
pass on cold cache-enabled scans; it does not change the asymptotic bound. With
`B` source bytes, `N` AST nodes, `V` files and `E` import edges, graph planning
and analysis remain expected `O(B + N + V + E)` time and `O(B + N + V + E)`
peak space across retained parent inputs, worker state, findings and digests.
Warm or partially populated caches still require a planning pass before cache
selection. The 50k sample is recorded in `docs/BENCHMARKS.md`; peak RSS remains
high, and repeated, concurrent and cross-platform profiling remains open.

Five isolated 50k cache-enabled cold-only runs completed with full coverage at
a median 18.85 s / 869 MiB sampled RSS (ranges 18.06–19.07 s / 861–899 MiB).
This adds within-host sample variance but does not establish p95, a stable
memory bound or a causal speedup over the previous single baseline. One
memory-instrumented pass initially had incomplete coverage in a later warm
pass after a complete cold pass. The cause was the optional `memory` message
from the plan worker being rejected by the plan client; the client now accepts
and reports that message, with a focused regression. An instrumented full
rerun completed. Raw repeated rows are in
`docs/benchmarks/toolip-v3.2.1-ast-cold-repeat-2026-11-08-linux-node24.jsonl`.

Warm cache handling no longer builds a returned dependency-digest map after
validating each serialized digest against the current worker plan. It also
reuses the validated findings map directly when every cache path hits, avoiding
a second `O(F)` findings-map copy; incremental invalidation still copies that
map before deleting paths that must be recomputed. This lowers live map space
on a full hit without changing time complexity. Five complete 50k cache cycles
measured median wall/RSS of 18.09 s / 866 MiB cold, 4.35 s / 1,006 MiB warm,
and 4.65 s / 1,199 MiB incremental. Ranges overlap prior single-run samples;
there is no causal improvement claim or memory bound. Raw data is in
`docs/benchmarks/toolip-v3.2.1-ast-cache-cycle-repeat-2026-11-08-linux-node24.jsonl`.

### Batch 07 cache capacity and worker memory gate (2026-11-09)

`AnalysisResultCache.get()` now treats V8 deserialization errors as misses,
evicts the corrupt payload, and lets the task scheduler recompute it. Cache
operations expose cumulative hits, misses and evictions, entry count, and
retained serialized payload bytes; counters add `O(1)` time and the retained
payload remains bounded by the existing 64 MiB aggregate and 4 MiB per-entry
caps. The byte counter excludes JavaScript `Map`, key and object overhead, so
process RSS/heap remain separate measurements.

The AST worker client now admits at most one worker and one waiting request per
process. A further request fails with an incomplete capacity reason. A queued
request has the same end-to-end timeout deadline as its worker and can be
removed immediately on cancellation. This bounds AST worker copies and queue
retention to at most one active input set plus one already-captured waiting
snapshot. Each worker has V8 limits of 512 MiB old generation, 128 MiB young
generation and a 16 MiB stack; those V8 limits do not cap total process RSS. A
50k cold full-scorecard run and a two-scan concurrent pair completed under the
lower ceiling. Their sampled RSS was 860 MiB and 1,036 MiB respectively, so the
change narrows the worker heap ceiling but does not prove a process-wide memory
budget. Expected planning/analysis work remains `O(B + N + V + E)` time and
`O(B + N + V + E)` worker live space for source bytes `B`, AST nodes `N`, files
`V` and import edges `E`.

On a validated incremental cache read, the findings map is now modified in
place instead of copied. That removes an additional `O(F)` map allocation and
copy for `F` AST files. The 50k incremental sample still peaked at 1,275 MiB
RSS, within the prior repeated range; this single sample does not show a
measurable memory reduction from that map change. The 50k concurrent-pair sample
under the one-worker gate peaked at 1,098 MiB RSS, compared with 1,366 MiB in
the earlier two-worker sample. These are single-run synthetic observations,
not a stable memory bound or release evidence. Raw current data is
`docs/benchmarks/toolip-v3.2.1-batch07-50k-worker-pool-linux-node24.jsonl`;
the immediately preceding cache-copy sample is also retained separately.

### Dependency lock graph trust checks (2026-11-09)

The npm v2/v3 package map is now shape-validated in one pass over package
records and their declared dependency maps. Construction uses a null-prototype
lookup so lock paths such as `__proto__` cannot mutate object inheritance.
Absent version records are surfaced as incomplete unless they are valid links;
`peerDependenciesMeta.optional` is validated, and only an explicitly optional
missing peer is omitted from unresolved edges. For `P` lock entries and `D`
dependency declarations, this validation and graph-index construction is
expected `O(P + D)` time and `O(P + D)` additional space.

Cross-ecosystem duplicate identities are checked once per record. Each record's
normalized dependency fingerprint sorts its `K` edges in `O(K log K)` time;
the total work is `O(sum(K_i log K_i))` over all `P` records, with `O(P + D)`
retained identity/fingerprint space and `O(max K_i)` temporary fingerprint
storage. Conflicting checksums, dependency edges or normalized resolution
confidence/context mark the package unknown and remove its trusted integrity
field. Python marker syntax is parsed under a 1,024-character, 256-token and
depth-32 limit; bounded suffix matching has an `O(L^2)` worst-case
character-copy bound per marker for `L <= 1,024`. Evaluation uses a bounded
target profile (4 KiB JSON, 11 environment values, at most 64 extras), parses
each expression once per evaluation and evaluates it for at most 64 selected
extras. For `Q` marker expressions, AST nodes `N <= 256`, and string-comparison
length `C <= 1,024`, worst-case target work is `O(sum(L_i^2) + 64·Q·N·C)` and
peak parser space is `O(L + N + 64)` per marker. Dependency matching retains
the existing 250,000 candidate-work budget; package/context/edge indexing is
`O(P + D)` for `P` identities and `D` declarations/edges, with `O(P + D)`
retained graph space. PEP 440 parsing intentionally returns unknown for
unsupported or out-of-safe-integer versions. The grammar requires PEP 508
whitespace around binary comparisons and boolean operators and rejects
nonstandard `=` comparisons. Unsupported dependency-group context and
unselected target variants remain incomplete.

Go vendor resolution builds one exact directory set for vendored files and one
module-path trie, rather than scanning all vendor paths for each manifest
package. For `F` Go files, source bytes `B`, `P` manifest package paths, `M`
module instances, `R` `go.mod` requirements, `Q` checksum records and `E` import
edges, sorting costs `O(F log F + M log M)`, package-directory, requirement
and checksum indexing costs `O(F + P + M + R + Q)`, and import lookup plus
final edge sorting costs `O(B + E log E)`. Build-directive parsing has a
bounded `O(F·L²)` suffix-copy worst case for directive length `L <= 4 KiB`; AST
evaluation adds `O(F·N·T)` with at most 512 nodes `N` and 128 target tags `T`.
Total time is `O(B + F log F + M log M + P + R + Q + F·L² + F·N·T +
E log E)`. Build-expression tokens are capped at 512 per source file and the
target profile at 4 KiB/128 custom tags. Peak additional space is
`O(F + P + M + R + Q + E + L)`, where `L` is the largest one-file source buffer;
the snapshot's captured file bytes remain owned by the caller. `go.mod` and
vendor reconciliation checks selected versions against requirements, explicit
exclusions, duplicate module paths and package-directory membership. Vendored
archive identity remains `unavailable`; a manifest and file-path match are not
a cryptographic content proof.

### Batch 08: license analysis, SBOM identity, and frozen upgrade installs (2026-11-09)

The integrated scorecard reuses the dependency-health inventory and snapshot
file source for optional license analysis rather than parsing the same lock
graph a second time. Grouping direct instances by exact package name and
version takes expected `O(D)` time and `O(D)` space for `D` inventory records;
the deterministic result sort is `O(U log U)` for `U` distinct direct
identities. Provider work is bounded to the configured concurrency `C <= 32`;
the deps.dev client caps each response at 1 MiB and bounds request/retry time.
Retained license entries and findings are `O(U)` plus bounded provider
responses. Incomplete dependency identity or metadata is reflected as partial
coverage instead of a clean result.

SBOM PURL construction validates ecosystem-specific normalized values through
`packageurl-js`; npm scoped names retain the canonical encoded namespace and
round-trip through the independent parser. Per-package normalization and
validation are linear in the PURL string length; overall generation remains
bounded by the already parsed dependency graph and the existing graph-index,
sorting, cancellation and output limits. No benchmark was repeated because
this batch does not alter the AST analysis or cache path.

Frozen upgrade installation resolves executable search directories once per
transaction. For `P` inherited PATH entries, canonicalization and metadata
checks use `O(P)` filesystem probes and `O(P)` temporary path storage, with
repository/worktree and temporary-directory entries excluded. Package manager
versions and declared `packageManager` pins are checked before frozen install;
lifecycle scripts remain disabled and the test command runs only after the
install gate. Real npm, pnpm, Yarn Classic and Yarn Berry fixtures exercise
these boundaries. These bounds do not turn package-manager processes into an
OS sandbox; provider/platform and independent security acceptance remain open.

### Batch 09 AST binding accuracy follow-up (2026-11-09)

`collectBindings` now records identifier assignments during its existing
syntax-tree walk. Straight-line writes resolve at each call's source position;
conditional writes and nested-function writes remain low-confidence dynamic
candidates only when a child-process target is possible. The pass sorts `W`
write events in `O(W log W)` time and retains `O(W)` event state. For `Q`
binding lookups it adds `O(Q log W)` expected lookup time, with a 256-step cap
on chained alias resolution, alongside the existing `O(N + A)` AST walk and
alias queue (`N` syntax nodes, `A` pending aliases). Additional peak state is
`O(W + A)`; source text and AST retention remain governed by the existing
snapshot/worker limits. A 300-write adversarial chain returns an unresolved
candidate instead of growing the JavaScript call stack. No 50k run was repeated
for this accuracy correction; it does not claim a performance improvement.

The fixed AST corpus now has 19 labeled synthetic cases across shell, SQL,
SSRF, XSS, prototype mutation and route-authorization heuristics: ten positive
and nine negative. The focused run has zero false positives among the nine
negative fixtures and zero false negatives among the ten positive fixtures.
These fixed-fixture counts are not a production precision estimate. Inline and
worker parity includes calls before/after writes and conditional alias writes.
The new harness dimension smoke is recorded in `docs/BENCHMARKS.md`; it is not
the required independent 1k/10k/50k campaign. Existing large raw benchmark rows
remain unchanged; the 100k/250k work stays beyond this PR's phase boundary.

### Snapshot-backed module re-export resolution (2026-11-09)

For `T` top-level statements, `I` imported names, `X` named/star exports and
`L` local declarations, the project resolver builds static import/export/local
indexes and module-local write events in `O(N + T + I + X + L + W log W)`
time and `O(I + X + L + W)` additional space, where `N` is traversed AST nodes
and `W` is indexed write events. The write scan propagates conditional and
closure context once through the bounded tree instead of walking each
assignment's ancestor chain separately.
Before this index, resolving `Q` aliases through modules with `T` statements
could rescan those statements for each hop, giving `O(QDT)` work for maximum
re-export depth `D`. The index removes those repeated syntax scans.
Named ESM re-exports, `export *`, local aliases and static CommonJS
`exports.name`/`module.exports` assignments are resolved only against the
captured source files. Default ESM bindings and default exports are included;
module-local writes are indexed only after lexical bindings exist, avoiding
cross-scope name collisions. For `Q` distinct `(source, export-name)` queries over
`V` files and `E` re-export edges, memoized resolution is expected
`O(Q(V + E))` in the worst case before bounds; TypeScript module-path lookup
cost is included per traversed edge. Resolution work is capped at 8,000,000
steps, nesting at 256, and cached export results at 1,000,000 entries. The
additional memo is therefore `O(min(QV, 1,000,000))` space beyond the index
and write-event state. Exceeding the work or cache cap throws inside the
killable project-analysis worker and produces
incomplete AST coverage; an over-depth possible child-process alias returns a
low-confidence unresolved candidate. These are explicit bounds, not a claim
that the resolver always completes a 50k-file project. Focused tests cover
multi-hop, star, default and namespace imports/exports, static CommonJS
forwarding, mutable and conditional exported aliases, shadowed `exports`, a
same-named local in an unrelated closure, a depth-over-limit chain, source
locations, and worker/inline parity.

The frozen resolver snapshot was run once at each scale on Linux x64 with Node
24.22.1. Each cold full offline scorecard used 512-byte source files, three
exported symbols per file, and eight planted AST rules in one file. All
scorecards and coverage were complete, all eight planted findings were
detected, and provider requests were zero. At 1k/10k/50k source files, wall
times were 1.14/5.03/20.79 seconds and sampled process RSS peaks were
394/633/967 MiB. The 50k run opened 50,003 files and read 25,600,244 bytes.
Fixture SHA-256 values and CPU/heap/RSS measurements are in
[`frozen resolver scale JSONL`](benchmarks/toolip-v3.2.1-batch09-module-index-frozen-scale-2026-11-09-linux-node24.jsonl).
The artifact SHA-256 is
`b3dbf3c93933f6f2086edf8dbf5e9d1052a8118e94f7dad06e933a9864bb5106`; its
source/test/runner diff SHA-256 relative to PR head
`3ce12f2948af4378e2dfd9845244f8a3afa976ec` is
`2e68326c471fa713ebc60016962e96a8c31ae9dbb2cc9144c96f17dff8a1209e`.
After collection, only source formatting, an unused-parameter removal and a
test-helper safety cleanup changed; scanner behavior was unchanged. These are
one cold sample per size, not repeated p50/p95 measurements, a memory bound, a
cross-platform result, or release qualification. Earlier raw benchmark
artifacts remain preserved and were not overwritten.

## Batch 10 threat-intelligence and history paths (2026-11-09)

- EPSS/KEV input is normalized and sorted for `K ≤ 200` CVEs in
  `O(K log K)` time and `O(K)` space. EPSS requests use batches of 20 and two
  workers; one KEV request may run alongside them, with at most three active
  requests, three attempts per request and a 4 MiB cap per response. Parsing,
  alias joins and audit breakdown construction are linear in accepted source
  bytes, CVE aliases and findings, plus bounded sorting. Unavailable or stale
  feeds remain explicit unknown factors in each priority record.
- OSV path indexing builds adjacency, BFS parents and bounded root-prefix
  pointers in expected `O(V + E)` time and `O(V + E)` space. A path lookup
  emits at most 64 package instances, so `F` vulnerability findings add
  `O(64F)` output work/space instead of materializing every ancestor path for
  every dependency. Findings are sorted in `O(F log F)` time. A 70-instance
  chain regression verifies the first 64 nodes and truncation marker. A path
  is labeled verified only when the exact edge path exists and the involved
  dependency inventories are complete. Fixed-version candidates are filtered
  against the exact OSV ecosystem/package identity; only a single matching
  candidate is offered as a direct upgrade suggestion.
- Advisory snapshot manifest generation visits `R` records and `V` OSV
  vulnerability entries in `O(R + V)` time; flush sorts `R` keys in
  `O(R log R)`, canonicalizes `B` bytes in `O(B)`, and uses `O(B + R + V)`
  peak additional space. The document is capped at 64 MiB and 200,000 records.
  Signer ID, source version, oldest captured-record age and declared ecosystems
  are validated or reported; the CLI cannot prove what ecosystems an external
  project requires.
- Authenticated history validates and rewrites at most 5,000 entries and 32
  MiB per transaction. Append, read, migration and rotation are `O(Bₕ + H)`
  time and `O(Bₕ + H)` additional space for serialized history bytes `Bₕ` and
  entries `H`. The HMAC itself adds `O(Bₑ)` work for the new serialized entry.
- npm package history sorts at most 10,000 dated releases in `O(V log V)` time
  and keeps `O(V)` version/date/event references. Lock instances are capped at
  1,000, provider concurrency defaults to six, and each packument is capped at
  8 MiB. Provider result joins are `O(I + F)` for instances `I` and signals
  `F`; parsed JSON object expansion is runtime-dependent. The latest five
  dated publisher/maintainer events carry exact version timestamps and
  pseudonymous identifiers; incomplete source history stays explicitly
  partial/unavailable.

These bounds are source-derived and backed by focused regression tests; they do
not replace cross-platform 1k/10k/50k resource measurements, a whole-process
memory profile, independent provider review or external ecosystem calibration.
No new large benchmark campaign was run for this code change.

## Batch 11 concurrency callback indexing (2026-11-09)

For `N` syntax nodes, `I` identifier references, `F` same-file function
declarations, and `P` Promise-all map patterns, the concurrency analyzer builds
the callback index, imported-pool index, and per-function side-effect memo in
linear AST passes. Callback wrappers are resolved only when their same-file
name is unique. The memo ensures each resolved function body is inspected once;
recursive and over-depth paths conservatively remain candidates, with callback
depth capped at 16. Pool suppression requires a direct call through a unique
`const` created by a literal `p-limit` import with concurrency from 1 through
32; shadowed factories, aliasing, property mutation, dynamic or larger values
do not suppress. The source-level import name is not proof of the installed
package's resolved identity, so package-alias resolution remains an explicit
limitation.

The added indexing and memo work is expected `O(N + P)` time and `O(N + P)`
additional space under hash-map behavior. The analyzer still
retains the parsed AST and findings; project AST depth/node limits apply before
analysis. Regression cases cover arbitrary `limit` wrappers, opaque external
callbacks, a shadowed `p-limit` factory, dynamic/over-cap/mutated pools and a
statically bounded pool. These focused cases establish behavior, not a whole
repository performance or memory bound.

## Dockerfile parsing and ARG substitution reviewed on 2026-11-14

For `B` bytes across eligible Dockerfiles, bounded input reads are limited by
the shared 20,000-file, 2 MiB-per-file and 64 MiB-total budgets. The parser
splits physical lines, records logical instruction fragments, and joins a
continued instruction once at flush; this avoids repeatedly copying the
growing prefix across `D` physical continuation lines. Parsing is `O(B)`;
supported global ARG expansion uses `O(B + X)` time and space, where rendered
expansion bytes `X` are capped at 8 MiB per Dockerfile. ARG lookup uses
expected `O(1)` map operations; unsupported modifiers, escaped references and
budget exhaustion stay unresolved and produce incomplete coverage. Only the standard
`docker/dockerfile:1` frontend family is recognized; custom/invalid frontend
selection is reported incomplete without fetching or executing it. The previous
continuation assembly repeatedly concatenated the prefix, with worst-case
`O(B²)` copied string bytes for one heavily continued instruction; it is now
linearized. A 2,000-line continued instruction regression checks the bounded
parser result and byte accounting, and an adversarial 1 MiB ARG reused across
FROM instructions checks the cumulative expansion cap and unknown result.
These source-derived bounds are not measured wall-time or process-RSS
benchmarks; broader Docker grammar, platform and whole-process memory
acceptance remain open (#40/#63/#86).

## Static shell `-c` target aliases added on 2026-11-14

For a bounded script with `B` source bytes, `A` literal assignments and `R`
references, the malicious-content analyzer and protected Stage A scanner now
also recognize an exact earlier local path alias supplied to `sh -c`,
`bash -c` or `zsh -c`. The extra regex pass is `O(B)` time and the target set
uses `O(R)` additional space; alias resolution remains depth-capped at 16 and
rejects reassigned, single-quoted, interpolated or otherwise ambiguous values.
Dynamic shell `-c` variables, shell `eval` text and variable-selected `exec`
targets mark the trace unknown instead of clean.
Positive repository and Stage A regressions verify the full entrypoint-to-file
trace without executing any content. This adds one static wrapper form; it does
not complete shell semantics or resolve constructed commands. Issue #95 and
the broader #40 corpus remain partial.

## Signed scan subject digests added on 2026-11-12

For `F` captured files, `B` captured bytes, `P` total path bytes, `V` resolved
package instances, `E` dependency edges and `G` serialized graph bytes:

- `ProjectSnapshot.sourceTreeDigest` hashes sorted, normalized path/content
  identities after snapshot capture. The added pass is `O(F log F + P)` time
  and `O(F)` temporary path-reference space. Snapshot reads and file hashing
  remain `O(F + B)`; the existing snapshot retains captured text up to its
  configured byte budget.
- `scanDependencies` canonicalizes and sorts resolved package instances,
  edges, unresolved edges and warnings before hashing the exact graph. This
  costs `O((V + E) log(V + E) + G)` time and `O(V + E + G)` temporary space,
  in addition to the graph itself. Canonical serialization is capped at 32 MiB;
  exceeding that limit follows the existing incomplete graph path and omits
  the graph digest.
- Signed report subjects bind both digests, the lock/config digests, selected
  rule-pack identity/trust/signer, and the report's finding and coverage data.
  Verification can require the expected source-tree digest to reject a valid
  signature for a stale source snapshot. This does not authenticate the
  external trust policy or prove scan coverage beyond the report's explicit
  status.

## Opt-in npm provenance verification added on 2026-11-12

For one exact npm identity, verification performs up to three sequential
public-registry requests: packument, exact lock-resolved tarball, and
attestation. Packument and attestation bodies each have an 8 MiB cap; the
tarball is SHA-512 hashed as a stream with a 32 MiB total cap and is not
retained as a complete archive. The signed statement is capped at 1 MiB and at
most 100 attestation records are examined. Work is `O(P + T + A)` for packument
bytes `P`, tarball bytes `T`, and attestation bytes `A`. Peak live space is
`O(P + A + C)`, where `C` is the current streamed response chunk/queue and is
bounded by the 32 MiB tarball limit; parsed JSON objects add space proportional
to their capped input bodies. Sigstore verification runs
in a disposable worker with a 64 MiB V8 old-generation limit, a 20-second hard
stop and a 5-second per-provider request timeout. Worker and native memory are
additional to that V8 old-generation cap and are not a strict process RSS
bound. Scan concurrency is limited by the shared provider budget (maximum 32);
SBOM generation uses concurrency 8. The policy is capped at 1 MiB and 5,000
package rules. Scoped package names are withheld unless the caller grants
public-scope consent. Failed, missing, mismatched and cancelled verification
never produces a verified status. A `verified` artifact result now requires
the downloaded tarball bytes, lock SHA-512, and signed SLSA subject digest to
match. Stage A reuses the SHA-512 digest from its exact archive scan and applies
a protected repository variable's package issuer, certificate identity and
source repository policy before installing the PR lock graph. Missing policy or
any unverified package blocks Stage A. Non-npm publisher provenance remains
incomplete; live GitHub Actions execution of this policy path and host-side
Stage A bootstrap/ruleset enforcement remain external.

For the Stage A fast path, the archive SHA-512 is reused, so each package needs
only packument and attestation requests. Canonical policy serialization and
hashing cost `O(P + N log N)` time and `O(P + N)` additional space for policy
bytes `P` and object nodes `N`, including key sorting. The 1 MiB policy cap,
5,000 package-rule cap, 100,000-node serializer budget and depth-64 limit bound
both Stage A and Stage B policy handling. Stage B recomputes the current policy
hash before accepting the approval artifact; a missing, malformed or changed
policy invalidates the prior approval.

## Exact npm release tarball attestation added on 2026-11-12

`readNpmTarballIdentity` gunzips the bounded archive and streams the tar parser
without extracting entries or executing package scripts. It limits compressed
bytes to 32 MiB, uncompressed tar bytes to 128 MiB, declared unpacked entry
bytes to 128 MiB, entries to 100,000, and `package/package.json` to 1 MiB. Tar
decompression, traversal, manifest parsing and SHA-512 hashing are `O(T + U)`
time for compressed bytes `T` and uncompressed tar bytes `U`; live archive
buffers are bounded by `T + U`, and manifest parsing by 1 MiB. The DSSE statement is capped at 1 MiB and
the bundle file at 16 MiB. Certificate verification runs in an isolated worker
with 64 MiB maximum V8 old-generation space and a 20-second deadline. That V8
limit excludes worker/native overhead and is not a total RSS guarantee. The
protected publish workflow signs and verifies the release `.tgz`, preserves
the bundle, and passes the same archive path to npm publish; local checks have
not exercised GitHub OIDC, the npm trusted publisher, or a live publication.

The operator evidence trust store is strict versioned JSON capped at 1 MiB and
100 Ed25519 key records. Parsing and PEM validation are `O(S + K)` time and
space for store bytes `S` and keys `K`; selection by exact key ID is expected
`O(1)`. Key activation windows, expiry, project identity, maximum evidence age
and immediate revocation are checked before report or SBOM signature
verification. Direct one-off key arguments remain available for explicit
migration, but do not provide rotation or revocation policy.

## Reachability request-name alias indexing — 2026-11-14

`ReachabilityAnalyzer` maps requested package names (including lockfile aliases)
to installed identities. Previously every alias edge scanned the accumulated
identity array with `.some()`. With `Eₐ` alias edges and up to `V` installed
instances for one request name, that join could take `O(Eₐ·V)` time. It now
maintains a `Set` of identity IDs per request name while retaining the ordered
arrays used by resolution. Index construction and alias joins take expected
`O(V + Eₐ)` time and `O(V + Eₐ)` additional space; these are expected hash-table
bounds, not deterministic worst-case guarantees. The existing exact Yarn PnP
alias integration fixture and the reachability suite verify alias-to-installed
identity behavior. The focused reachability suite passed 9 tests and
`npm run typecheck` passed on Linux Node 24. This local optimization does not
complete the repository-wide #40 audit or its scale/operation-count acceptance.

Yarn `node_modules` discovery also compared every candidate package manifest
against the full locked-instance array for its install name. With `D` visited
package directories and `Vᵧ` expected Yarn instances concentrated under one
name, manifest validation could take `O(D·Vᵧ)` time. A per-install-name set of
exact `name\0version` keys is now built in `O(Vᵧ)` expected time/space, and the
bounded discovery loop validates each candidate with expected `O(1)` membership
work, for `O(Vᵧ + D)` expected time and `O(Vᵧ)` additional space. The outer
visited-entry cap remains 100,000. The indexed key adds work proportional to
the compared name/version bytes, and hash-table bounds remain expected-time.

## Authorization query ownership proof tightened — 2026-11-14

The AST authorization heuristic previously accepted any nested occurrence of
`req.user` under selected relation names, including projected `select` data,
and treated object expressions or request-selected identity properties as
direct identity values. The predicate now recognizes only direct identifier,
property or literal-key element identity expressions with recognized identity
claim names, plus bounded positive ownership filters. Relation IDs are
accepted only through direct predicates or positive `is`/`some` relation
constraints; OR branches still all need a scoped predicate. For `N` AST nodes
in the query expression, the added structural checks take `O(N)` time and
`O(min(N, 32))` recursive stack space due to the existing depth-32 query
limit. Adversarial cases cover projected relation selection, a negative tenant
predicate, request-selected identity properties, role claims and relation depth
over the cap; existing
fixtures cover direct tenant and shared-grant filters. The focused authorization suite passed 17 tests and TypeScript
typecheck passed. This syntactic heuristic still cannot prove framework,
database or application-policy semantics; #61 remains incomplete.

Explicit authorization calls now suppress candidates only when the call is
unconditionally executed before the object lookup. Calls inside optional
branches, short-circuit right operands, loops, switch cases, try/catch blocks
and catch clauses stay unproven, since a caught assertion failure may continue
to the lookup. The check walks the call's AST ancestor chain (`A` nodes), so its
additional time is `O(A)` and temporary space is `O(1)` per candidate call.
Boolean guards retain the separate fail-closed branch check. This is still
syntactic evidence and does not establish helper behavior or database policy
semantics (#61).

## Imported outbound request sink indexing — 2026-11-14

The SSRF pass identifies named imports from `node:http`, `node:https` and
`undici`, namespace imports from those modules, and default/named request
exports from `axios` and `got`, including local import aliases. It also indexes
top-level `const` bindings from a static literal `require()`, including
namespace, destructured named and axios/got default forms, unless `require` is
shadowed at module scope. For a source file with `T` top-level statements, `I`
imported bindings, `R` statically required bindings and `C` outbound calls,
standalone analysis previously rescanned the full statement list at each
recognized call (`O(C·T)`). It now builds one import map in `O(T + I + R)`
expected time and uses expected `O(1)` lookups per call, for
`O(T + I + R + C)` expected total time and `O(I + R)` additional map space.
Project analysis already had a per-source import map and now shares the same
builder. These map bounds are expected-time. Regressions cover ESM and
CommonJS named, namespace and default aliases with local shadowing; the focused
security suite, AST worker suite and typecheck pass. Dynamic modules and
project wrappers remain unresolved candidates (#60).

## Filesystem check/use operand coverage — 2026-11-14

The same-function race heuristic covers recognized open, stream, directory,
metadata and mutation methods. Rename, copy, hard-link and symlink operations
check both path operands against earlier checks. Calls to unrelated methods are
skipped before building their ancestor set. With `D` declarations and `C`
recognized filesystem calls, alias indexing remains `O(D)`; resolution is
expected `O(C × (A + H))` for AST ancestor depth `A` and alias chain cap
`H ≤ 16`, with at most two operands per call. The analyzer remains a candidate
heuristic; it does not establish canonical containment or prove freedom from
symlink and provider races (#60).

## Yarn Classic local alias identity — 2026-11-14

Yarn Classic `file:` descriptors can use an alias that differs from the local
package manifest name. The resolver now loads each unique local manifest once,
validates exact name/version identity and uses that manifest to construct the
package instance and dependency edges. Relative paths are normalized beneath
the project root; symlinked directory segments, out-of-root paths, absent
manifests and lock/manifest version mismatches remain unresolved. The resolver
shares the existing workspace-manifest budget: at most 10,000 manifests, 1 MiB
per manifest and 32 MiB aggregate. For `L` distinct local file targets and
captured manifest bytes `B`, indexing is expected `O(L + B)` time and `O(L + B)`
additional space within those limits (#64).

## Bounded file reads, report output, and issue #40 current rerun (2026-11-14)

`readBoundedRegularFile` rejects symlinks and non-regular inputs, checks the opened handle against pre-open and post-read device/inode/size/mtime/ctime identities, allocates at most `maxFileBytes + 1`, and reads in 64 KiB chunks. For an accepted file of `B` bytes it uses `O(B)` time and `O(min(B, 64 KiB) + B)` memory for the returned byte buffer plus the bounded caller result; mutable `B` is capped by the caller's configured budget. A replacement or in-place mutation is reported as incomplete input. Lockfile inputs retain their 64 MiB cap. Regression fixtures cover symlink rejection, invalid UTF-8, exact limits and changed-input rejection.

`serializeJsonOutputWithinBudget` streams JSON fragments into bounded output chunks, caps bytes at 64 MiB, traversal at one million nodes, depth at 256 and fragments at one million, and rejects cycles/accessors/BigInt. It uses `O(N + B_out)` time and `O(B_out + D)` additional space for traversed nodes `N`, serialized bytes `B_out`, and active depth `D ≤ 256`; it preflights escaped strings before `JSON.stringify` creates the escaped copy. These limits bound serialization, not caller-owned input graphs or subsequent write buffers. Tests exercise escaped oversized strings, artifact-specific ceilings, cycles, accessors and depth.

The current 54-row Linux Node 24.22.1 benchmark is recorded in `docs/BENCHMARKS.md` and `docs/benchmarks/toolip-v3.2.1-issue40-final-2026-11-14-linux-node24.jsonl`. It reports complete coverage at 1k/10k/50k files; the 50k incremental scan still samples 627 MiB heap and 1,267 MiB process RSS, and the concurrent pair 418 MiB heap / 1,041 MiB RSS. The large retained peaks show why this does not close #40/#56: ecosystem parser buffers, cross-feature snapshot retention, and whole-process concurrent live-space accounting still require source review and measured remediation. Later Batch 17/18 integrations also remain in the retrospective #40 audit scope.

### #56 snapshot indexing and digest serialization — 2026-11-14

`createProjectSnapshot()` now canonicalizes discovered paths once, streams the previous-snapshot and reuse maps instead of materializing tuple/value arrays, and hashes lock/config entries and the snapshot ID incrementally. Each JSON tuple is still materialized for one entry at a time; the complete `files` JSON string and its tuple array are no longer simultaneously allocated. Path sorting remains `O(F log F)`, capture and hashing remain `O(B)`, and the retained snapshot, previous/reuse maps, and content array remain `O(F + B)`. Streaming digest temporaries are bounded by the largest serialized per-file tuple, but this does not bound the retained source text or total process RSS. `dependencyFileSourceFromSnapshot()` constructs its path list and content index once per immutable snapshot (`O(F)` references/map entries plus the existing strings), then reuses that view across consumers through a `WeakMap`. Snapshot and scorecard tests check canonical JSON digest equivalence, reordered discovered-path determinism, shared dependency reads, and cache identity. The 1k/10k/50k rerun is documented in `docs/BENCHMARKS.md`; it remains a single Linux Node 24 sample and still reaches 1,246 MiB RSS on the 50k incremental case and 1,035 MiB for a concurrent pair. Cache churn, invalidation storms, cancellation-under-load, whole-process memory budgeting and cross-platform verification remain open for #56.

## Malicious-content execution-chain scale — #95 (2026-11-15)

`analyzeMaliciousContent()` sorts `F` captured files in `O(F log F)`, indexes paths/content in expected `O(F)`, scans `B` captured text bytes, then traverses a bounded `V` entrypoint/reference graph with `E` edges in `O(V + E)` expected time. Peak retained input/index space is `O(F + B)` plus bounded reference/graph state `O(V + E)`. Per-file content analysis is digest-cached with 1,024 entries and at most 256 cached references per content; the caller caps input at 100,000 files, 2 MiB per file and 256 MiB total, while entrypoint/reference work has explicit limits. Linux Node 24.22.1 isolated 1k/10k/50k synthetic runs took 20.09/119.49/366.75 ms, scanned 32 KB/320 KB/1.6 MB, returned one complete three-file trace, and sampled 230/221/287 MiB peak RSS. This is one sample at each scale, not variance or cross-platform evidence; raw results are in `docs/benchmarks/toolip-v3.2.1-issue95-malicious-content-2026-11-15-linux-node24.jsonl`. Archive extraction chains remain explicitly unknown because extracted contents are unavailable; dynamic runtime construction and accuracy calibration remain incomplete (#95).

### #56 process-wide isolated-worker budget — 2026-11-15

`AnalyzerRunner` instances share a FIFO worker pool with two active slots and
at most 256 queued requests with the analyzer deadline applied while waiting. Across all runners in one Node process, isolated
workers therefore have a combined configured V8 old-generation limit no
higher than twice the per-worker setting (1 GiB at the 512 MiB default).
Enqueue, dequeue, cancellation and timeout removal are `O(1)` per worker
using a doubly linked FIFO queue; `Q ≤ 256` bounds retained waiter state. Queued requests can be
cancelled; active slots are held through actual worker termination. The bound
does not cover process RSS, in-process analyzers, separate processes, or the
memory held by queued caller inputs. Focused runner tests verify aggregate
concurrency, queued cancellation and queue-deadline enforcement. #56 remains open for whole-scan memory
accounting, cache churn/invalidation stress, and cross-platform evidence.

### #91 computed outbound sensitive-data sinks — 2026-11-15

`sensitiveOutputSink()` now recognizes literal and dynamic computed method
calls on known loggers, response objects, outbound clients, and telemetry
receivers, and URLSearchParams instances. For a dynamic computed method, detection is conservative and only
uses a recognized receiver family; static property names still use the
existing per-method allowlists. This adds constant work per call to the
existing bounded AST traversal and does not attempt arbitrary runtime alias or
client resolution. The sensitive-flow and AST analyzer suites pass 59 tests;
typecheck and targeted lint pass on Linux Node 24.22.1. Findings retain
redacted source evidence. Dynamic module loading, external serializer/redactor
contracts and false-positive calibration remain open.

### #89 statically computed transaction calls — 2026-11-15

The discarded-transaction heuristic now recognizes literal and
no-substitution-template computed method names such as
`db['$transaction'](...)` and `database['transaction'](...)` on
recognized database client roots. Arbitrary computed keys remain unclassified.
This adds constant work per call to the existing AST walk. The focused
concurrency suite passes 23 tests, with typecheck and targeted Biome checks
passing on Linux Node 24.22.1. Cross-file promise ownership, Redis/lock
semantics, transaction isolation and broad corpus calibration remain open.

### #91 statically resolved outbound client aliases — 2026-11-15

Sensitive-flow analysis now recognizes default, namespace and named imports
from supported outbound client packages, plus direct literal `require()`
aliases. The alias is tracked in its lexical scope and a shadowing local
binding stops the recognition. Computed client methods and direct imported
`node-fetch` calls can therefore reach the existing outbound-request sink
model without trusting arbitrary variables or runtime resolution. Binding
collection adds one set insertion per imported/required binding; sink checks
walk the existing lexical scope chain. The sensitive-flow and AST suites pass
60 tests with typecheck and targeted lint passing on Linux Node 24.22.1.
Transitive re-exports, dynamic module names, custom clients and redactor
contracts remain unsupported and explicitly outside the proof.

### #60 and #91 supported external HTTP client sinks — 2026-11-15

The bounded AST model now identifies outbound-client aliases from a fixed
package allowlist (`axios`, `node-fetch`, `undici`, `got`, `ky`, and related
HTTP clients) through imports and literal CommonJS `require()` calls. Named
imports are restricted to known request functions; arbitrary imported classes
are not treated as sinks. Identifier resolution respects lexical shadowing.
Direct `require(moduleName).get(url)` and `import(moduleName).request(url)`
receivers, plus dynamically loaded local namespace and destructured-method
aliases, are retained as SSRF candidates without including the module name in
evidence; the analyzer does not resolve or execute those modules. Immutable
alias propagation is capped at 16 passes over pending bindings. Re-export
chains and custom wrappers remain unresolved. The sensitive-flow and AST
suites pass 60 tests with typecheck and targeted lint passing on Linux Node
24.22.1. This is a static API model, not runtime client discovery or
URL/redirect safety proof (#60).

### #91 explicit sensitive-schema tags — 2026-11-15

The checker recognizes a fixed set of seven lowercased JSDoc tags on resolved
property declarations (`sensitive`, `confidential`, `pii`, `personaldata`,
`phi`, `protectedhealthinformation`, `toolipsensitive`). Tag checks use a
module-level `Set`, so each declaration lookup is expected `O(1)` per tag;
existing checker and source traversal bounds are unchanged. This is explicit
annotation support, not inferred database schema classification.

### #56 snapshot discovery-list preflight — 2026-11-15

`createProjectSnapshot()` now checks the caller-provided discovery-list length
against the configured `maxFiles` before spreading/copying the list. This
rejects oversized metadata in `O(1)` time and additional space before any
per-entry validation; accepted inputs retain the existing `O(F)` copy/sort
and `O(F + B)` snapshot bounds. A proxy-backed regression throws if iteration
starts before the cap check. Snapshot and scorecard suites pass 35 tests,
with typecheck and targeted Biome checks passing on Linux Node 24.22.1. This
closes only the preflight allocation gap, not whole-scan RSS or cache
cancellation accounting.

### #61 Next.js route-context parameters — 2026-11-15

Exported `GET`/`POST`/`PUT`/`PATCH`/`DELETE`/`OPTIONS` handlers now seed the
second context parameter, including only the `params` field from destructured contexts, as
request-controlled input. Existing same-handler alias propagation then
identifies object lookups using direct `context.params.id` and awaited,
destructured `params` values. The added context scan is `O(P)` in the number
of handler parameters and binding elements, within the existing AST traversal
budget. Authorization tests pass 22 cases with typecheck and targeted Biome
checks passing on Linux Node 24.22.1. Nested policy engines, cross-module
ownership contracts and corpus accuracy remain open.

Ownership analysis also follows a bounded set of relation names into nested
tenant membership, grant, group, team and shared-resource predicates. It only
accepts a nested predicate when it reaches an authenticated identity and keeps
request-controlled membership identities as candidates. For `N` properties in
the bounded query object, the added traversal is `O(N)` time with recursion
limited to 32 relation levels. A per-query weak memo stores at most two proof
bits per visited object node, giving `O(N)` auxiliary space and preventing
mutual ownership/relation checks from revisiting nested subtrees. Unsupported
relation shapes remain unresolved.

### #95 additional archive formats — 2026-11-15

Archive execution classification now recognizes `bsdtar`, `7za`/`7zz`, RAR
`x`/`e`, and Java `jar x*` extraction followed by a Java `-jar` launch or
other supported executable target. The bounded regex scan remains `O(B)` in
captured script bytes; extracted archive contents are never opened or
executed. Malicious-content plus Stage A suites pass 107 tests, with typecheck
and targeted Biome checks passing on Linux Node 24.22.1. Archive-derived
traces remain explicitly unknown; dynamic/runtime extraction and broad
accuracy calibration remain open.

### #95 `7zr` extraction recognition — 2026-11-15

The same bounded archive-pattern pass now includes `7zr x` and `7zr e` while
leaving `7zr a` creation outside the extraction rule. Local malicious-content
and protected Stage A fixtures passed 141 tests together. The added regex arm
preserves `O(B)` scan time and constant pattern space. The full verification
gate passed: 1,410 unit tests (4 skipped), 1,408 coverage tests (3 skipped),
85.55% statements, 79.62% branches, 93.16% functions and 88.14% lines.

### #95 Node archive-library extraction APIs — 2026-11-15

The bounded archive API patterns now include `AdmZip.extractAllTo()`, Node
`tar.x()`/`tar.extract()`, `shutil.unpack_archive()`, `unzipper.Extract()` and
`extractZip()`, paired with common child-process and Deno command launch APIs.
The analyzer and trusted Stage A fixtures passed 151 tests together, including
a negative archive-creation case. The scans remain linear in the bounded
source window; they do not unpack or execute archives. Full verification
passed with 1,423 unit tests (4 skipped), 1,421 coverage tests (3 skipped),
85.62% statements, 79.66% branches, 93.16% functions and 88.21% lines.

The same bounded pattern set now includes `decompress()` and
`node-stream-zip` extraction calls. The malicious-content and Stage A suites
passed 156 tests, including a benign event-listener control. The complete
verification gate passed with 1,428 unit tests (4 skipped), 1,426 coverage
tests (3 skipped), 85.55% statements, 79.62% branches, 93.16% functions and
88.14% lines. The scan remains linear in the bounded source window and does
not inspect archive contents.

### #37 scoped npm PURL manager matrix — 2026-11-15

The scoped npm PURL conformance fixture now covers npm lockfile v2/v3, pnpm v9,
Yarn Classic and Yarn Berry, validating canonical PURLs through both SBOM
formats and `packageurl-js`. The fixture suite passes 27 tests; this adds no
production-path work or complexity.

### #40 bounded SSRF host-allowlist proof work — 2026-11-15

Per-file AST analysis now shares a 250,000-node budget across URL host-guard
and mutation proofs. Each traversal charges visited syntax nodes; once the
budget is exhausted, no remaining host proof can suppress a candidate, so
outbound tainted requests remain SSRF findings. This caps repeated
`hasVerifiedFetchHostAllowlist()`/`mutatedBetween()` work at `O(W)` with
`W ≤ 250,000` per analyzed file, instead of multiplying whole-function
traversals by the number of outbound calls. Static host lists are limited to
256 entries and candidate expressions to 4,096 source units, bounding work
that occurs inside each proof. The AST security suite passes 47 tests with typecheck and targeted Biome checks passing on Linux Node 24.22.1.
A 400-call fixture exercises repeated proof work while preserving findings on
budget exhaustion; a 257-host fixture verifies oversized allowlists remain
unverified. Broader cross-feature CPU/RSS audit and scale measurements
remain open for #40.

### #60/#89 realpath check-then-use candidates — 2026-11-15

The filesystem race heuristic now treats `realpath` and `realpathSync` as
checks when their input path is later reopened or mutated. This adds two
constant-size method entries to the existing bounded source scan and keeps the
finding as a low-confidence race candidate; it does not prove canonical path
containment or close the symlink replacement window. The concurrency suite
passes 24 tests with typecheck and targeted Biome checks passing on Linux Node
24.22.1. Canonical descriptor-safe handling, cross-file flows and broader
race accuracy remain open for #60/#89.

The same #60/#89 follow-up resolves a local `realpath()`/`realpathSync()`
result back to its input path when checking later file operations. Alias
resolution is limited to 16 links, so this adds `O(D)` work for alias depth
`D ≤ 16` per file operation. Regressions cover both reopening the original
path and reopening the canonical result. This detects the pattern; it does not
make the check atomic or prove race-free access.

### #95/#96 imported process and archive API candidates — 2026-11-15

The local malicious-content pass and trusted Stage A pass now recognize fixed
child-process imports through named/default/namespace ESM, CommonJS
destructuring and namespace bindings, literal dynamic imports, local method
aliases, computed calls and nonliteral module resolution. Each proof uses a
fixed number of bounded regex passes over a source file capped at 2 MiB in the
local pass and 2 MiB per candidate in Stage A; names are stored in sets, so
work is linear in captured bytes for these checks. Command-line archive
patterns cover common tar/7-Zip/RAR/JAR/PowerShell/Python forms. Python
`ZipFile`/`TarFile` extraction API checks limit the constructor-to-extraction
span to 1 KiB and inspect at most 2 KiB after extraction for process launches.
Archive-derived chains stay unknown because archives are not unpacked. The
malicious-content and Stage A suites pass 133 tests; the fixed 4-benign /
3-suspicious regression corpus records zero errors but does not estimate field
accuracy. Cross-platform profiling and broader adversarial corpora remain open
for #40/#95/#96.

### #56 estimated worker-context clone budgets — 2026-11-15

Before starting an isolated analyzer, `AnalyzerRunner` estimates the snapshot
clone payload in one pass over `F` file records, adding each recorded byte
count, path allowance and fixed metadata allowance. This adds `O(F)` time and
constant loop space, without serializing the snapshot into a temporary buffer.
Requests above 320 MiB are rejected; the process-wide pool allows at most 640
MiB of estimated active clone inputs and 512 MiB of queued inputs, in addition
to the two-worker cap. The pool also reserves worker V8 old-generation limits
under a process-wide 1,024 MiB aggregate ceiling, even when separate runners
request larger per-worker limits. Regressions verify oversized requests do not
start and two maximum-heap workers run sequentially. These are clone-payload
reservations and V8 limits, not a total RSS bound: worker runtime allocations,
parent snapshot retention, native memory and other concurrent work remain
outside this estimate. The analyzer-runner enforcement suite passes 16 tests;
#56 remains incomplete pending measured whole-process memory and cancellation
under load.

### #40 stream-decode tracked Git paths — 2026-11-15

`trackedEntries()` now parses NUL-delimited `git ls-files -z` output directly
from its bounded buffer, decoding one path at a time. This removes the full
listing string, the `split()` array of every path and a second UTF-8 round-trip
buffer. Time remains `O(L)` for listing bytes `L`, while live working memory
falls from `O(L + F)` additional copies to `O(F)` retained path strings plus
one decoded path, with `L` still capped by Git's 64 MiB output limit. A
regression verifies newline and Unicode path names. The file-walker suite
passed 10 tests; typecheck, targeted Biome and `git diff --check` passed. This
reduces one discovery allocation but does not complete the repository-wide
#40 audit.

### #40 Cargo optional-feature indexing — 2026-11-15

Cargo feature resolution now builds a per-module alias-to-declarations index
once, then reuses it for feature activation. It no longer scans all feature
definitions for every optional dependency or all declarations for every
dependency-feature edge. For `D` declarations and `F` feature entries, this
removes the prior `O(D × F)` optional-feature scan; index construction is
`O(D + F)`, with target filtering limited to declarations sharing the
requested alias. Optional dependency aliases remain inactive unless reached
from an active feature, matching Cargo's feature semantics. A 1,200-optional
dependency regression asserts that unused aliases produce no active features
or graph edges. Ecosystem, SBOM and OSV suites pass 140 tests; typecheck and
targeted Biome pass on Linux Node 24.22.1. Broader workspace feature/cfg
qualification and the remaining codebase-wide #40 inventory remain open.

The extended benchmark harness measured 1k/10k/50k optional declarations at
33.93/119.91/451.86 ms with sampled heap peaks of 56.4/63.9/142.2 MiB and
RSS peaks of 214.5/223.1/333.1 MiB. The 50x input increase took 13.3x the
single-run wall time. Raw evidence and fixture hashes are in
`docs/BENCHMARKS.md`; this is a single-run local curve, not percentile or
cross-platform evidence.

Cargo workspace root-edge construction previously scanned all `L` lockfile
dependency records for each of `D` manifest declarations. It now indexes lock
records by exact package name, manifest alias and target context once, then
checks only identity-matched records against the declared version requirement.
This changes the matching work from `O(D × L)` to expected `O(D + L + K)`,
where `K` is the number of version candidates sharing an indexed identity.
A 1,200-dependency regression asserts exact root-edge and package counts. The
same isolated 1k/10k/50k wide-root fixture measured 189.09/884.05/3,009.26 ms
and sampled 60.9/126.1/351.4 MiB heap peaks; raw data and hashes are in
`docs/BENCHMARKS.md`. These single Linux runs do not provide percentiles or
cross-platform evidence.

### #89 Redis check-then-set detection — 2026-11-15

Redis concurrency analysis indexes immutable local `get`/`exists` results by
variable, and candidate `set`/delete writes by receiver and static key once per
function. Each condition's identifiers are visited once; a binary search finds
the first same-key write in the branch, and one finding per key is emitted.
The receiver index follows unique, visible, immutable `const` aliases up to
16 links. With `D` declarations, `C` calls, `Q` conditional-expression
identifier occurrences, `H ≤ 16` alias hops and `R` findings, the added pass
is `O(D + C × H + Q log C + R)` time and `O(D + C + Q)` bounded-by-source
memory. Dynamic keys and unresolved/mutable receivers remain outside the
model. The concurrency suite covers 256 independent same-function keys plus
immutable and mutable receiver aliases; full distributed-lock and cross-file
modeling remain open for #89.

Discarded database transaction detection uses the same per-function declaration
index and follows unique visible immutable `const` receiver aliases up to 16
links. For `D` declarations, `C` calls and `H ≤ 16` alias hops, this adds
`O(D + C × H)` expected time and `O(D + C)` source-bounded space; mutable or
ambiguous receiver aliases remain unresolved.

### #91 schema-classified browser disclosure sinks — 2026-11-15

Explicit property decorators are checked through their declaration symbols.
Built-in `FormData` and `WebSocket` receiver names are indexed once per lexical
scope and cached by constructor kind; subsequent sink checks use set membership
while walking lexical parents. This avoids scanning the scope's statements
again for each `append`, `set` or `send` call. Cross-file local serializer
returns follow the resolved AST project graph. Custom redactors are trusted
only when annotated and statically return a literal or null. Full verification
passed with 1,433 unit tests (4 skipped), 1,431 coverage tests (3 skipped),
85.55% statements, 79.62% branches, 93.16% functions and 88.14% lines.
