# Toolip Engineering Standards

Toolip is a security tool. Engineering choices must therefore optimize for truthful claims, explicit failure, bounded work, and simple invariants before abstraction or convenience.

## First principles

- Prefer one authoritative model over parallel implementations.
- Prefer ten clear lines that preserve the same correctness/security/scale guarantees over thirty lines of ceremony.
- Do not add an abstraction unless it owns a real invariant, lifetime, boundary, or replacement point.
- Do not optimize by weakening security checks, losing determinism, or hiding failure.
- Reuse discovered project/dependency state instead of repeating filesystem/network work.

## Correctness

Security findings must distinguish confirmed behavior from heuristic indicators. Findings carry confidence and stable rule identity.

Toolip must not:

- represent an unmeasured security dimension as `100/100`
- represent provider failure as “no vulnerabilities” or equivalent safety
- use physical npm hoisting as proof of root-direct dependency status
- treat static non-observation as proof of unreachability
- downgrade a real secret merely because it appears under a test path

## Canonical contracts

Internal security analysis uses one normalized `Finding` contract. Compatibility-specific report shapes belong at serializers/output boundaries.

Resolved package identity is derived from one manifest/lockfile inventory and reused across dependency features.

## Error handling

Expected failures use typed/stable errors where practical. Network providers distinguish unavailable, timeout, malformed, authorization, and partial responses.

Analyzer execution isolates sibling failures and exposes timeout/cancel/failure status explicitly.

## Performance and scale

- Repository discovery should happen once per execution where possible.
- Source reads must be bounded by explicit budgets.
- Avoid loading entire histories/large outputs when they can be processed incrementally.
- Network fan-out must use bounded concurrency.
- Avoid O(n²) correlation when a one-time map/index makes the relationship direct.
- Preserve deterministic result order even when execution is concurrent.
- Do not add caches whose documented lifetime exceeds their actual process/storage lifetime.

## Filesystem safety

Filesystem authorization uses canonical resolved paths, not textual prefix checks.

MCP roots must remain inside configured approved workspaces after symlink resolution.

Mutable Git workflows should isolate changes in temporary worktrees when rollback/dirty-tree safety matters.

## Secrets and local state

- Raw secrets must not appear in normal findings/reports.
- Prefer masking plus irreversible fingerprints for correlation.
- Shell output must be encoded for the shell representation it claims to support.
- Encrypted vault writes must be serialized and atomic.
- Corrupt vault state fails closed rather than being treated as empty data.

## Testing

Every meaningful behavior change requires the most direct test that proves the guarantee.

Prefer behavioral tests over source-code string inspection.

Security/reliability fixes should include adversarial regression cases such as traversal, symlink escape, non-cooperative timeouts, duplicate secrets, dirty worktrees, concurrent vault mutations, provider failure, and cross-platform path behavior.

The normal quality gate includes:

1. changelog verification
2. Biome lint (warnings are errors) and Prettier formatting (repo docs/config/scripts in full; source and tests on changed files)
3. workflow release-isolation/permission policy and lockfile integrity
4. production and development dependency audit (every severity) plus registry signature verification in CI
5. compiler-backed static quality checks
6. complete behavioral test suite
7. security-critical V8 coverage thresholds
8. clean build
9. built-package verification

CI additionally runs Gitleaks and CodeQL. Coverage thresholds are floors, never to be lowered to pass; a failing gate is reported as failing.

Security-critical coverage floors are 75% statements/lines, 65% branches, and 85% functions.

## Cross-platform support

`package.json#engines.node` defines supported, securely patched runtime ranges. CI must execute every supported major on Ubuntu, macOS, and Windows using the newest patch release, and fail when the runtime is outside `engines`.

A platform-specific native runtime failure is a product compatibility bug when Toolip depends on the failing path; do not dismiss it as CI flakiness without evidence.

## Concurrency, cancellation and races

- Check-then-use on filesystem state is a defect: open once and operate on the handle, or use atomic rename/exclusive-create.
- Every timeout must abort the underlying work (AbortSignal propagation), not only stop waiting for it.
- Shared mutable state needs a documented owner and serialization strategy; results must not depend on scheduler order.

## Privacy

Toolip remains local-first. Reports redact secrets by default. Remote publishing and GitHub operations are opt-in and must make clear what leaves the machine.

## Releases

A release is not complete when source tests pass. The generated npm tarball must be installed in isolation and the packaged CLI must run successfully.

Ordinary CI does not receive npm publish credentials. Release/publish authorization is isolated behind dedicated workflows and least-privilege permissions.

## Required algorithmic complexity evidence for every v3.2.1 PR

Document the input dimensions and **worst-case time and peak additional space Big-O before and after** each changed hot path. Distinguish file count `F`, bytes `B`, dependency nodes `V`, edges `E`, symbols `S`, rules `R`, and concurrent tasks `C`. Include map/index construction, queues, recursion depth, cache lifetime and peak buffered data. Big-O is not a benchmark.

| Concern                       | Target technique                                               | Avoid unless justified                               |
| ----------------------------- | -------------------------------------------------------------- | ---------------------------------------------------- |
| Source scanning               | Bounded single-pass or streaming traversal, ideally `O(F + B)` | Repeated full directory walks or unbounded buffering |
| Dependency graphs             | Adjacency indexes and `O(V + E)` traversal                     | Redundant `O(V²)` graph passes                       |
| Correlation and deduplication | Hash-indexed expected `O(n)` joins                             | Nested `find`/`includes` scans                       |
| Ordered output                | One necessary `O(n log n)` sort                                | Re-sorting within inner loops                        |
| Dataflow/AST                  | Bounded worklists, memoized resolution                         | Unbounded path explosion or recursive exploration    |
| Provider requests             | Deadline-limited and concurrency-bounded `C`                   | Unlimited fan-out or indefinite retries              |

The PR template's complexity table is mandatory; PR reviewers must reject unexplained asymptotic or peak-memory regressions. Validate claimed improvements with representative and pathological fixtures and time/CPU/peak RSS benchmarks, including 1k/10k/50k-file repositories as relevant. Set actual budgets from measured baselines, not invented numbers. Correctness, security coverage, deterministic results and truthful failure handling outrank micro-optimizations.

## Batch and release discipline

Follow [the 20-batch roadmap](V3.2.1-IMPLEMENTATION.md). One batch yields one PR with separate typecheck/build/test/style/security checks and the existing Node/OS CI matrix. Completed issues close on merge to `main`. Normal PRs/merges must not publish npm or create a GitHub release. Those operations require explicit, manual authorization after the entire v3.2.1 scope is complete.
