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

## Mandatory single-push policy — minimize GitHub Actions and CodeRabbit costs

**NON-NEGOTIABLE: NO INTERMEDIATE / INCREMENTAL / CHECKPOINT PUSHES.** For each implementation batch, the default budget is **exactly one consolidated remote push**, made only once the complete batch is implemented, self-reviewed and locally verified. If the owner explicitly authorizes combining batches in one PR (as with Batches 05 + 06), treat the combined scope as one unit for this rule. The number of local commits is unrestricted; the number of remote pushes is not. GitHub Actions and CodeRabbit must not be used as a substitute for local development or debugging.

1. **Read and plan first:** inspect `AGENTS.md`, all linked issues and acceptance criteria, affected code, relevant CI requirements, and all existing review findings. Include known security/edge cases, documentation and regression coverage in the implementation plan.
2. **Finish everything locally:** implement the full batch and its documentation, security corrections, tests and integration. Make local commits as useful; do **not** `git push`, force-push, open a partial PR merely to trigger CI, or push cosmetic or single-finding fixes. Do not ask GitHub to diagnose problems that can be reproduced locally.
3. **Mandatory final local gates:** run `npm ci --ignore-scripts`, `npm run verify`, `npm run release:check`, and all applicable formatting/lint/typecheck/build/test/coverage, runtime and dependency vulnerability audits, registry signature/attestation audits, Gitleaks, packed-artifact verification, and targeted concurrency/security/regression tests. Review the entire changed-file diff, test assumptions and platform-specific behavior. Fix failures and repeat checks locally until green. Never report unrun checks as passed.
4. **One push after final sign-off:** consolidate the entire verified implementation and push it **once** to the batch PR branch, then let remote quality/security CI, CodeQL, CodeRabbit and Node 22/24 Linux/macOS/Windows checks run. A GitHub push is not a progress update; report progress without pushing.
5. **External review exceptions are rare and batched:** if CodeRabbit or remote CI exposes issues not reasonably discoverable locally, collect **all** current findings, validate which are real, fix all valid problems together locally, add regression tests, and rerun the entire applicable local verification. Then and only then may there be **one consolidated corrective push**. Do not push one fix per comment or repeatedly trigger new CodeRabbit runs. Resolve review threads only after the fixes are demonstrably complete. Repeat only when genuinely new external findings make another correction unavoidable.
6. **Never evade safeguards to reduce CI costs:** do not skip tests, reduce coverage, hide findings, fabricate green checks, dismiss valid comments or bypass branch protections. When validation cannot be completed locally, do not push; report the blocker.
7. **PR and merge discipline:** normally one branch and one PR per batch unless the owner explicitly authorizes combining batches. Once checks and all required independent approvals succeed, **always squash merge** into `main` (never a merge commit or rebase merge). Verify the resulting squash commit, then close completed linked issues and update epic #88. Never directly push to `main`.
8. **Release restrictions remain absolute:** no npm publication, release workflow, version tag or GitHub release until the entire v3.2.1 release is finished and the owner explicitly authorizes publication.

**Cost-control objective:** comprehensive local verification first; one implementation push per batch/authorized combined PR; at most one consolidated corrective push per completed external review cycle when strictly necessary. Never trade security or correctness for fewer CI minutes.

