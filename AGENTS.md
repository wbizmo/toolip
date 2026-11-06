# Toolip Agent and Contributor Instructions

Applies to all changes in this repository. Read `CONTRIBUTING.md`, `docs/ENGINEERING.md`, `SECURITY.md`, `RELEASING.md` and `docs/V3.2.1-IMPLEMENTATION.md` before implementation.

## Release and Git rules

- Work on one v3.2.1 batch at a time; one branch and one PR per batch; never push directly to `main`.
- Push code changes for PR review and automated quality/security CI, **not for npm publication**.
- Do not trigger `publish.yml` or `github-release.yml` during intermediate batches, create a release tag or advance the published package version.
- Only the final authorized release workflow may publish npm. Require exact main/tag/version matching and verified tarball.
- Use `Closes #N` only if the PR fully addresses the issue and is intended to close it on merge; otherwise use `Refs #N`.
- Preserve truthful current v2.2.1 documentation until v3.2.1 is verified and approved. Do not rewrite historical release notes as if new features were shipped.

## Correctness, security and complexity

- No silent partial successes: timeouts, skipped files, unknown packages and unavailable providers are not clean.
- Never print raw secrets, execute untrusted project code to inspect it, weaken auth/containment, or disable a failing test for convenience.
- Bound filesystem and network work, CPU-intensive analysis, recursion, memory, cancellation and concurrency. Handle symlinks, TOCTOU, stale locks, process crashes and Git staged-versus-working-tree differences.
- Per PR, identify input dimensions (e.g. files F, bytes B, dependency vertices V, edges E, symbols S) and explicitly state worst-case **time and space Big-O before/after**. Do not assume indexing is free; include build cost and memory.
- Prefer O(F+B) streaming file scans, O(V+E) adjacency-based graph traversal, O(n) hash-index joins and O(n log n) necessary sorting. Avoid O(n²) nested correlation when stable indexing is possible.
- Measure representative baselines and 1k/10k/50k-file workloads for performance-sensitive changes. A Big-O assertion alone is not proof; benchmark and profile.
- Every security change adds behavioral and negative/adversarial fixtures; tests and reports must remain deterministic under bounded concurrency.
- Keep code understandable; optimization must never weaken threat boundaries, security coverage or failure reporting.

## Engineering standards (required)

- Choose efficient algorithms and data structures; state explicit worst-case time **and** space complexity for every changed hot path. Avoid unnecessary O(n²) processing.
- Bound memory, filesystem operations and network concurrency. Every long operation accepts cancellation and a deadline, and cleans up on both.
- Protect against races and TOCTOU: operate on opened handles or canonical resolved paths, not check-then-use; write state atomically.
- Behavior must be deterministic and testable; no wall-clock, ordering or environment dependence without injection.
- Secure defaults and least-privilege permissions everywhere, including GitHub Actions (`contents: read` by default, write scopes only at job level, third-party actions pinned to full commit SHAs).
- Never place raw secrets in logs, reports, test snapshots or CI artifacts.
- Every bug fix ships a regression test that fails without the fix.
- Report coverage and failures accurately: never lower thresholds, skip tests or mark checks non-blocking to get green; never describe an unrun check as passed.
- Dependency advisories are fixed by upgrading (or a documented `overrides` entry); never suppress, ignore or downgrade findings. Do not run `npm audit fix --force` blindly; evaluate each breaking change.

## PR quality

PRs must pass locked dependency install, TypeScript typechecking, compiler-backed checks, Biome lint, Prettier formatting, workflow/lockfile policy, build, tests, coverage thresholds, production and development dependency audit with signature verification, secret scanning, CodeQL and the Linux/macOS/Windows × Node 22/24 CI matrix. Run `npm run verify` locally first. Review any scanner finding instead of assuming either a false positive or an automatically exploitable vulnerability.

Do not auto-merge; report CI failures and fix before merging. The owner authorizes the final release separately.

## Mandatory push and CI cost policy

- **NO INTERMEDIATE, INCREMENTAL OR CHECKPOINT PUSHES.** Finish the entire batch locally before pushing. Default to exactly one implementation push per completed batch or explicitly authorized combined-batch PR. Local edits and commits are allowed; progress, speculative fixes and partial implementations must never be pushed.
- **Read scope before coding.** Review every linked issue, acceptance criterion, existing review finding and affected path. Include security, edge cases, documentation, platform behavior and regression tests in the local implementation.
- **Run all local checks before pushing.** Complete `npm ci --ignore-scripts`, `npm run verify`, `npm run release:check`, tests, coverage, formatting, lint, typechecks, build, dependency and runtime audits, registry signature audits, Gitleaks and packed-package verification as applicable. Correct failures locally and rerun the relevant checks. Never claim a check passed unless it ran.
- **Push only the final locally verified changeset.** Consolidate all batch changes and push once. Let GitHub Actions, CodeQL, CodeRabbit and the Node 22/24 Linux/macOS/Windows matrix evaluate the completed PR. Do not use remote CI as a local debugging loop.
- **Consolidate corrections from each external review cycle.** Collect and validate all CodeRabbit, CI and independent-review findings, including locally discoverable issues. Fix valid findings together locally, add regression coverage and rerun the applicable full local verification. A single consolidated corrective push is permitted when genuinely necessary, **even if the review cycle contains only one valid finding**. Do not push separately for each comment. Repeat only for new, verified blockers.
- **Never sacrifice correctness to reduce cost.** Do not skip tests, lower coverage, hide findings, dismiss valid review comments, or bypass branch protection. Do not push unverifiable changes. Resolve review threads only after verifying their underlying corrections.
- **Always squash merge.** Normally use one branch and one PR per batch unless the owner explicitly authorizes combining batches. After required CI, review resolution and independent approval, squash merge into `main`; never use a normal merge commit, rebase merge or direct push to `main`. GitHub may automatically close issues referenced by `Closes #N` at merge; verify the squash commit before any manual issue closure or epic #88 update.
- **Never publish intermediate work.** No npm publication, version tag or GitHub release is permitted during routine v3.2.1 batches. The exception in `RELEASING.md` permits an urgent compatible v2.2.x security hotfix before v3.2.1 only with separate explicit release approval, the required release guards and a deliberate version/tag. Routine PR merges do not authorize publication; final v3.2.1 publication also requires explicit owner approval.

**Cost objective:** one implementation push per completed batch or approved combined PR, plus at most one consolidated corrective push per completed external review cycle when required. Preserve all security and quality gates.
