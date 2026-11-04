# Contributing to Toolip

Toolip welcomes focused bug fixes, security-rule improvements, provider integrations, performance work, documentation corrections, and tests that strengthen observable guarantees.

## Development setup

Toolip supports patched Node.js 22 (>=22.23.4) and 24 (>=24.22.1, 24.22.2+ recommended); the floors live in `security/runtime-floors.json`.

```bash
npm ci
npm run verify
```

## Engineering expectations

- Keep analyzers independent from CLI presentation.
- Return normalized findings through the canonical `Finding` contract.
- Use stable rule IDs and stable occurrence identity where multiple findings can exist per file/rule.
- Redact sensitive evidence by default.
- Treat provider failure explicitly; never turn failure into a clean result.
- Reuse project/dependency context instead of repeating expensive discovery.
- Avoid unbounded file reads, memory accumulation, or network concurrency.
- Preserve deterministic output where concurrency is used.
- Prefer the smallest implementation that preserves correctness, security, scale, and portability.
- Keep remote operations opt-in.
- Do not weaken the packed-artifact release verification path.

## Tests

Prefer behavioral tests over implementation/source-string checks.

A bug fix should include a regression test that would have failed before the fix. Security and portability work should include adversarial cases where relevant, such as:

- traversal/symlink escape
- duplicate secrets
- non-cooperative timeout/cancellation
- provider failure
- concurrent vault mutation
- dirty Git worktrees
- nested dependency versions
- cross-platform path/watcher behavior

The security-critical coverage gate must remain at or above 75% statements/lines, 65% branches, and 85% functions.

## Pull requests

A pull request should explain:

- the problem being solved
- the chosen invariant/design
- why the solution is no more complex than necessary
- important security/performance/compatibility tradeoffs
- tests added
- user-visible behavior
- release/documentation implications

Run `npm run verify` (changelog, lint, formatting, workflow policy, lockfile integrity, dependency audit, typecheck, quality, tests, coverage, build, package smoke test) before pushing; it must pass locally. Source and tests are format-checked on changed files only (`npm run format:changed`) so style cleanup never forces repo-wide rewrites; do not reformat untouched files. All CI jobs must pass before merge, including supported Node majors across Linux, macOS, and Windows plus packed npm artifact verification.

## Release-affecting changes

If a change affects commands, security claims, Node support, package behavior, release automation, or user-facing semantics, update the relevant README/docs/changelog in the same release cycle.

`package.json` remains the only package-version source of truth.

## v3.2.1 sequential batch PRs

Follow the [20-batch roadmap](docs/V3.2.1-IMPLEMENTATION.md) and [AGENTS.md](AGENTS.md). Each completed batch is pushed on its own branch as one PR. Use `Closes #N` only for fully resolved issues; these close **when merged to main**, not when opened. For partially addressed issues use `Refs #N`.

Every PR runs the existing cross-platform CI and `.github/workflows/pr-quality.yml`: typechecking, compiler-backed quality, build, tests, production dependency audit, changed-source Biome lint/format, YAML Prettier and Gitleaks, plus CodeQL from `.github/workflows/codeql.yml`. Installs use `npm ci --ignore-scripts`. The PR jobs have no npm publication credentials.

### Mandatory Big-O performance review

Each PR must report inputs and old/new worst-case **time and peak space complexity** for changed hot paths, including indexing cost and memory. Prefer `O(V + E)` graph traversal, `O(n)` indexed joins, and streaming bounded file reads over avoidable `O(n²)` correlations. Benchmark and profile meaningful performance changes, including 1k/10k/50k-file scales when appropriate. Security or correctness must never be weakened to improve theoretical or measured cost.

The PR template contains the required complexity table. No intermediate PR may publish npm, create a GitHub release or advance published version metadata. Only the final authorized v3.2.1 release does so.
