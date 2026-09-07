# Contributing to Toolip

Toolip welcomes focused bug fixes, security-rule improvements, provider integrations, performance work, documentation corrections, and tests that strengthen observable guarantees.

## Development setup

Toolip v2.2 supports Node.js 22 and 24.

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

All CI jobs must pass before merge, including supported Node majors across Linux, macOS, and Windows plus packed npm artifact verification.

## Release-affecting changes

If a change affects commands, security claims, Node support, package behavior, release automation, or user-facing semantics, update the relevant README/docs/changelog in the same release cycle.

`package.json` remains the only package-version source of truth.
