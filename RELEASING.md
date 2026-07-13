# Releasing Toolip

Toolip releases are verified from the npm tarball that users will install. A successful local build alone is not sufficient.

## Release Requirements

Before beginning:

- The working tree must be clean.
- CI must pass on Linux, macOS, and Windows.
- The package version must not already exist on npm.
- `package.json` must be the only version source.
- Release notes and the changelog must describe only verified changes.

## Required Sequence

1. Install dependencies with `npm ci`.
2. Update the version in `package.json`.
3. Update `CHANGELOG.md`.
4. Run `npm run release:check`.
5. Inspect the generated tarball.
6. Confirm the packed CLI reports the expected version.
7. Confirm packed `self-test` and `--help` succeed.
8. Authenticate with npm.
9. Publish the verified package.
10. Query npm and confirm the published version.
11. Download the published tarball.
12. Verify the published tarball again.
13. Install the published package in a clean prefix.
14. Run version, self-test, and help checks.
15. Commit and push release metadata.
16. Create and push the Git tag.
17. Create the GitHub release with accurate notes.

## Mandatory Guard

Run:

```bash
npm run release:check
```

A release must not be published unless that command exits successfully.

The guard verifies:

- type checking
- the full test suite
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

## npm Authentication

```bash
npm login --auth-type=legacy --registry=https://registry.npmjs.org/
npm whoami --registry=https://registry.npmjs.org/
```

## Publishing

Publishing is intentionally not automated by `release:check`. A human must review the verified artifact before running:

```bash
npm publish --access public --registry=https://registry.npmjs.org/
```
