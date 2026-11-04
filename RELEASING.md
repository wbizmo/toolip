# Releasing Toolip

Toolip releases are verified from the npm tarball that users will install. A successful source-tree build alone is not sufficient.

## Release requirements

Before beginning:

- the release branch must contain the complete user-facing documentation for the version
- `CHANGELOG.md` and `RELEASE_NOTES_vX.Y.Z.md` must describe only verified changes
- `package.json` is the only package-version source of truth
- `package-lock.json` must be synchronized with the package version/dependency graph
- CI must pass on every supported Node major across Linux, macOS, and Windows
- the packed npm artifact verification job must pass
- the target version must not already exist on npm or as a conflicting GitHub release/tag

## Supported runtime

`package.json#engines.node` is authoritative. The unreleased v3.2.1 branch declares the range below (the published v2.2.1 declares `>=22 <25`):

```text
^22.23.4 || >=24.22.1 <25
```

The floors are the Node.js releases that contain the October 2026 security fixes (22.23.4, 24.22.1; 24.22.2+ recommended) and are tracked in `security/runtime-floors.json`. `engines` alone does not block installs, so the CLI also refuses to run on unpatched runtimes (see `docs/RUNTIME-AND-DEPENDENCY-SECURITY.md`). CI executes the newest Node.js 22 and 24 releases (`check-latest`) on Ubuntu, macOS, and Windows and runs `scripts/verify-node.mjs` so an unsupported or unpatched runtime fails the job.

## Mandatory verification

Run:

```bash
npm run verify
```

The normal gate includes:

- changelog verification
- compiler-backed static quality checks
- production dependency audit (`npm audit --omit=dev --audit-level=high`)
- complete behavioral tests
- security-critical V8 coverage
- clean production build
- built-package verification

Security-critical coverage floors are:

- 75% statements
- 75% lines
- 65% branches
- 85% functions

For a release candidate, also run:

```bash
npm run release:check
```

The release guard verifies the exact npm tarball, including:

- all normal quality/security gates
- required package contents
- CLI shebang
- package/version synchronization
- packed `README.md` and `LICENSE`
- isolated tarball installation
- packed `toolip --version`
- packed `toolip self-test`
- packed `toolip --help`

## PR batches are not releases

The [Toolip v3.2.1 implementation schedule](docs/V3.2.1-IMPLEMENTATION.md) has 20 separately reviewed PR batches. A branch push or PR merge to `main` must **never** invoke npm publishing or GitHub release creation. Fully resolved GitHub issues close on merge, not when a PR is opened.

Normal CI (`.github/workflows/ci.yml`, cross-platform build/test/coverage and packed-artifact verification) and the independent `pr-quality.yml` (typecheck, compiler-backed quality, Biome lint, Prettier formatting, workflow and lockfile policy, actionlint, build/tests/coverage, production and full dependency audit with registry signature verification, and Gitleaks) run without npm credentials. CodeQL runs from the single `codeql.yml` workflow on PRs, pushes to `main` and weekly, so PR alerts compare against main's baseline (a separate PR-only CodeQL job made GitHub report "1 configuration not found"). Every `npm ci` uses `--ignore-scripts` so dependency lifecycle scripts do not run during installation; tests and builds still execute repository code until Stage A exists (see SECURITY.md). `audit.yml` re-runs the full dependency audit and signature verification on every push to `main` and weekly, because advisories appear against unchanged code. `scripts/verify-workflows.mjs` fails CI if any workflow other than the two manual release workflows can publish, tag or read release secrets, if any action is not pinned to a full commit SHA, or if write permissions are declared at workflow level. The package version and current-release docs remain truthful for v2.2.1 until final release preparation.

## Manual GitHub release

`.github/workflows/github-release.yml` has **only** the `workflow_dispatch` trigger and accepts an exact version plus the confirmation `release toolip`. It must run on `main`, verify matching `package.json`, changelog and release notes, and pass `npm run release:check` before creating the tag and GitHub release. Do not dispatch before every v3.2.1 batch is approved and merged.

## Manual npm publication

`.github/workflows/publish.yml` also has **only** `workflow_dispatch`; it is not triggered by PRs or merges. It requires an exact version, `publish toolip` confirmation, `main`, an existing verified GitHub release with tag matching the exact HEAD commit, an unpublished npm version, and the packed package verification guard. The `npm-release` environment should have required reviewers configured by a repository administrator.

`publish.yml` no longer reads `NPM_TOKEN`. It publishes with npm trusted publishing: the job requests a GitHub OIDC identity (`id-token: write`, granted only to that job), npm exchanges it for a short-lived publish credential and attaches provenance. **Prerequisite (owner action, not verifiable from the repository):** register `wbizmo/toolip` + `publish.yml` + environment `npm-release` as a trusted publisher in the npm package settings, and remove any stored `NPM_TOKEN` secret. Until that is configured the workflow fails closed rather than falling back to a token. Issue [#55](https://github.com/wbizmo/toolip/issues/55) stays open until a real trusted publish has been verified. A named GitHub environment has **no mandatory review** unless the environment's protection rules are actually configured.

## Final release sequence

1. Complete, review and merge all 20 PR batches with clean quality/security and Node/OS verification. Update master epic #88, and confirm every original implementation issue is closed.
2. In the final release PR, set version to `3.2.1` in `package.json`, synchronize `package-lock.json`, update README and living docs, create the changelog entry and `RELEASE_NOTES_v3.2.1.md`.
3. Validate advisories, the benchmark/fuzzing budgets, packed tarball installation, CLI smoke tests, signatures/provenance, cross-platform CI and `npm run release:check`.
4. Obtain explicit owner approval for public release.
5. Manually dispatch `github-release.yml` on `main` with version `3.2.1` and confirmation `release toolip`. Verify tag `v3.2.1` points to the intended exact commit.
6. Separately manually dispatch `publish.yml` on `main` with version `3.2.1` and `publish toolip`. Verify installed package, registry version and provenance after publishing.

## Emergency exceptions

If an urgent compatible v2.2.x security hotfix is needed before v3.2.1, it needs separate explicit release approval, the same guards and a deliberate version/tag. A routine merge does not authorize an emergency publication.
