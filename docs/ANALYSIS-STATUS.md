# Analysis status, exit codes and isolation

Toolip never reports "clean" for work it did not complete. Every analysis ends in one of three states.

| State      | Meaning                                                                                                                            |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `complete` | Every eligible input was examined. A clean result is a real all-clear.                                                             |
| `partial`  | Some eligible inputs were skipped, failed, cancelled or timed out. Findings are real; absence of findings is **not** an all-clear. |
| `failed`   | The analyzer failed or timed out, or nothing eligible could be examined.                                                           |

JSON output (`--json`) includes an `analysis` block with `state`, `complete`, `reason`, `eligible`, `scanned`, `skipped` and `failed`. Human output prints the state to stderr whenever it is not `complete`.

## Exit codes

| Code | Meaning                                                                                   |
| ---- | ----------------------------------------------------------------------------------------- |
| 0    | Complete (or partial with `--no-fail-on-incomplete`), no gated findings                   |
| 1    | Usage/runtime error; for `pre-commit`, blocking findings                                  |
| 2    | Complete run with findings at or above `--fail-on`                                        |
| 3    | Partial analysis (`--fail-on-incomplete`, default for analyzer commands and `pre-commit`) |
| 4    | Failed analysis or nothing could be scanned                                               |

`--fail-on <critical|high|medium|low|info|none>` sets the findings gate. `--no-fail-on-incomplete` can tolerate partial coverage in non-staged scans, including explicit `pre-commit --full` runs. **Staged pre-commit always blocks unexamined eligible inputs**, even with the opt-out flag. Nothing-scanned/failed analysis always exits 4; when findings and incomplete coverage coexist, the highest applicable exit code wins.

## Enforceable analyzer termination

A timeout in a single JavaScript thread cannot interrupt synchronous CPU work. Analyzers that declare `isolation` (the AST analyzer) run in a `worker_thread`; on deadline or cancellation the runner terminates the worker and waits for it. In-process analyzers get a deadline and `AbortSignal`; if they ignore it, they are reported `unresponsive` after a grace period rather than as stopped. Concurrency is capped and results keep input order, so sibling analyzers still report when one times out or fails.

## Scan budget for registry lookups

`scorecard` and dependency scans share a budget: a 1–600,000 ms overall deadline, `AbortSignal`, a 1–600,000 ms per-request timeout and provider concurrency from 1–32. Transient failures (429/5xx/network) retry at most five times, honouring `Retry-After` with jitter capped at 60 seconds. Invalid caller-supplied budgets or retry settings are rejected. Malformed registry responses fail closed. Unmeasured dependencies make the dependency dimension "unmeasured" and the run `partial`, never a healthy score.

## Optional dependencies

`install-scripts` counts an uninstalled optional package as `excluded` only when the lockfile's `os`/`cpu`/`libc` constraints prove npm omits it on the current platform. Linux libc is detected only from positive runtime evidence; unknown libc never justifies exclusion. An optional package without such proof, or whose manifest cannot be accessed, is `skipped` and makes the run `partial`.

## Complexity

Let F be eligible files, B bytes, D dependencies, A analyzers, C concurrency.

| Path                | Time before → after                          | Space before → after    |
| ------------------- | -------------------------------------------- | ----------------------- |
| Coverage accounting | — → O(F)                                     | — → O(1)                |
| Analyzer runner     | O(A) → O(A) wall O(A/C)                      | O(A) → O(A + C workers) |
| Dependency lookups  | unbounded → O(D/C) requests, bounded retries | O(D) → O(D)             |
