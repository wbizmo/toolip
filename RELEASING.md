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

`package.json#engines.node` is authoritative. Toolip v2.2.x currently declares:

```text
>=22 <25
```

CI executes Node.js 22 and 24 on Ubuntu, macOS, and Windows.

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

Normal CI (`.github/workflows/ci.yml`) and the independent `pr-quality.yml` check typechecking, compiler-backed quality, build, tests, dependency audit, changed-file lint/format, Gitleaks and CodeQL without npm credentials. The package version and current-release docs remain truthful for v2.2.1 until final release preparation.

## Manual GitHub release

`.github/workflows/github-release.yml` has **only** the `workflow_dispatch` trigger and accepts an exact version plus the confirmation `release toolip`. It must run on `main`, verify matching `package.json`, changelog and release notes, and pass `npm run release:check` before creating the tag and GitHub release. Do not dispatch before every v3.2.1 batch is approved and merged.

## Manual npm publication

`.github/workflows/publish.yml` also has **only** `workflow_dispatch`; it is not triggered by PRs or merges. It requires an exact version, `publish toolip` confirmation, `main`, an existing verified GitHub release with tag matching the exact HEAD commit, an unpublished npm version, and the packed package verification guard. The `npm-release` environment should have required reviewers configured by a repository administrator.

The current npm workflow still uses an environment-scoped `NPM_TOKEN`. Issue [#55](https://github.com/wbizmo/toolip/issues/55) must replace/harden it with least-privilege npm trusted publishing/OIDC and provenance before final v3.2.1 publication. Do not falsely describe the current token path as OIDC-only. A named GitHub environment has **no mandatory review** unless the environment's protection rules are actually configured.

## Final release sequence

1. Complete, review and merge all 20 PR batches with clean quality/security and Node/OS verification. Update master epic #88, and confirm every original implementation issue is closed.
2. In the final release PR, set version to `3.2.1` in `package.json`, synchronize `package-lock.json`, update README and living docs, create the changelog entry and `RELEASE_NOTES_v3.2.1.md`.
3. Validate advisories, the benchmark/fuzzing budgets, packed tarball installation, CLI smoke tests, signatures/provenance, cross-platform CI and `npm run release:check`.
4. Obtain explicit owner approval for public release.
5. Manually dispatch `github-release.yml` on `main` with version `3.2.1` and confirmation `release toolip`. Verify tag `v3.2.1` points to the intended exact commit.
6. Separately manually dispatch `publish.yml` on `main` with version `3.2.1` and `publish toolip`. Verify installed package, registry version and provenance after publishing.

## Emergency exceptions

If an urgent compatible v2.2.x security hotfix is needed before v3.2.1, it needs separate explicit release approval, the same guards and a deliberate version/tag. A routine merge does not authorize an emergency publication.
