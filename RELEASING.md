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

`package.json#engines.node` is authoritative. Toolip v2.2.0 supports:

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

## GitHub release and tag

`.github/workflows/github-release.yml` owns GitHub release creation.

When a version/release-notes change is merged to `main`, the workflow:

1. reads the exact version from `package.json`
2. requires `RELEASE_NOTES_v<version>.md` to exist
3. validates that the matching tag/release does not already conflict
4. runs `npm ci` and `npm run release:check`
5. creates `v<version>` pointing at the verified `main` commit
6. creates the GitHub release using the checked-in release notes and the title declared by the workflow

The GitHub tag therefore points at a commit that contains the version, README, changelog, release notes, release workflow, and all code included in that release.

GitHub release creation does **not** publish the npm package.

## Preferred npm publish path: GitHub OIDC

`.github/workflows/publish.yml` owns npm publication and is separate from normal CI/GitHub release creation.

The publish job receives only the permissions required for npm trusted publishing:

- `contents: read`
- `id-token: write`

It does not expose npm authorization to ordinary pull-request/CI jobs.

Configure the npm package once with this trusted publisher:

- provider: GitHub Actions
- GitHub owner: `wbizmo`
- repository: `toolip`
- workflow filename: `publish.yml`
- environment: `npm-release`

For stronger human review, configure the GitHub `npm-release` environment with required reviewers.

The npm workflow is manually dispatched from `main`, requires the exact version plus explicit authorization text, reruns the full release guard, rejects an already-published npm version, and publishes using npm trusted publishing/OIDC with provenance.

## Release sequence

1. Complete/fix the release scope on a branch.
2. Set the new version in `package.json` and synchronize `package-lock.json`.
3. Update `README.md`, `CHANGELOG.md`, relevant docs, and `RELEASE_NOTES_vX.Y.Z.md`.
4. Ensure the PR's complete CI matrix and packed-artifact verification are green.
5. Merge to `main`.
6. Allow `github-release.yml` to verify `main`, create tag `vX.Y.Z`, and publish the GitHub release from the checked-in notes.
7. Verify the GitHub tag/release points to the intended verified commit.
8. Only when npm publication is explicitly authorized, manually dispatch `publish.yml` on `main` with the exact version and confirmation text.
9. Verify the npm package/version/provenance after publication.

## Emergency npm fallback

The preferred npm path is OIDC. If GitHub Actions or npm trusted publishing is unavailable and an emergency manual release is genuinely required:

1. run the same `npm run release:check` guard
2. authenticate interactively with npm using a short-lived or appropriately scoped credential
3. publish the exact verified package
4. verify the published artifact
5. revoke/expire the emergency credential

Do not place a long-lived npm publish token in ordinary CI jobs.
