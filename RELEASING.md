# Releasing Toolip

Toolip releases are verified from the npm tarball that users will install. A successful local build alone is not sufficient.

## Release Requirements

Before beginning:

- The working tree must be clean.
- CI must pass on Linux, macOS, and Windows for every supported Node.js version.
- The package version must not already exist on npm.
- `package.json` must be the only version source.
- Release notes and the changelog must describe only verified changes.
- The GitHub Actions trusted publisher must be configured on npm before the automated publish path is used.

## Supported Runtime

`package.json#engines.node` is authoritative. CI must test every supported major release represented by that range.

## Mandatory Guard

Run:

```bash
npm run release:check
```

A release must not be published unless that command exits successfully.

The guard verifies:

- compiler-backed static quality checks
- no high/critical npm advisories in the shipped runtime dependency graph
- the full test suite
- security-critical execution coverage thresholds
- a clean production build
- the CLI shebang
- version synchronization
- `README.md`
- `LICENSE`
- `dist/src/index.js`
- isolated installation of the packed artifact
- packed `toolip --version`
- packed `toolip self-test`
- packed `toolip --help`

## Preferred Publish Path: GitHub OIDC

Toolip uses `.github/workflows/publish.yml` for manually authorized npm releases. The workflow has no long-lived npm token. Its publish job receives only `contents: read` and `id-token: write`, allowing npm to exchange GitHub's OIDC identity for short-lived publish authorization.

Configure the npm package once with this trusted publisher:

- provider: GitHub Actions
- GitHub owner: `wbizmo`
- repository: `toolip`
- workflow filename: `publish.yml`
- environment: `npm-release`
- allowed action: direct `npm publish`

For stronger human review, configure the GitHub `npm-release` environment with required reviewers. The workflow is already restricted to manual dispatch from `main` and requires both the exact package version and the confirmation text `publish toolip`.

The release job uses Node.js 24 and npm 11.5.1 or newer because npm trusted publishing requires a sufficiently recent npm CLI. Trusted publishing automatically produces npm provenance for this public package/repository.

## Automated Release Sequence

1. Update the version in `package.json`.
2. Update `CHANGELOG.md` and release notes.
3. Merge only after the normal CI matrix is green.
4. Open **Actions → Publish npm package → Run workflow** on `main`.
5. Enter the exact package version without a leading `v`.
6. Enter `publish toolip` as the authorization text.
7. Approve the `npm-release` environment deployment if reviewer protection is configured.
8. The workflow installs exact dependencies, runs `npm run release:check`, rejects an already-published version, and publishes through npm trusted publishing.
9. Query npm and verify the published version and provenance.
10. Create and push the matching Git tag and GitHub release with accurate notes.

## Manual Emergency Fallback

The preferred path is OIDC. If GitHub Actions or npm trusted publishing is unavailable and a manual release is genuinely required, run the same `npm run release:check` guard, authenticate interactively with npm using a short-lived or appropriately scoped credential, publish, and revoke/expire that credential afterward. Do not add a long-lived publish token to ordinary CI jobs.
