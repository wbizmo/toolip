# Package manager resolver fixtures

These lockfiles were generated with the pinned package-manager versions below, using scripts-disabled, lockfile-only or no-build installs:

- `npm-v2`: npm 11.9.0, `--lockfile-version=2`
- `npm-v3`: npm 11.9.0, `--lockfile-version=3`
- `pnpm-v8`: pnpm 8.15.9, lockfile format 6
- `pnpm-v9`: pnpm 9.12.3, lockfile format 9, workspace linking enabled, optional peers not auto-installed
- `yarn-classic-v1`: Yarn 1.22.22
- `yarn-berry-v2`: Yarn 2.4.3, lock metadata format 4
- `yarn-berry-v3`: Yarn 3.8.7, lock metadata format 6
- `yarn-berry-v4`: Yarn 4.5.0, lock metadata format 8

The npm, pnpm, and Yarn Classic cases share `project/`. The Berry cases use separate workspace-only manifests because Berry records workspace identities with synthetic local versions. Registry tarballs in the npm, pnpm and Yarn Classic locks are manager-generated public package output; recorded integrity values are declarations, not proof that Toolip independently verified the artifacts. Berry workspace lockfiles contain no registry artifacts; optional missing peers are declared by the captured manifests.

The resolver golden test checks graph cardinalities and key edge targets for
these generated fixtures, then checks exact alias targets, npm
install paths, workspace edges, distinct PURL multiplicities and reachability
for actual alias install directories. Expected graph sizes are:

| Generated fixture | Packages | Edges | Registry package coverage |
| ----------------- | -------: | ----: | ------------------------- |
| npm lockfile v2   |       13 |    19 | React 18/19, npm aliases, transitive and nested hoisted dependencies |
| npm lockfile v3   |       13 |    19 | React 18/19, npm aliases, transitive and nested hoisted dependencies |
| pnpm lockfile v6  |       11 |    17 | React 18/19, aliases and peer-qualified `react-dom` store paths |
| pnpm lockfile v9  |       11 |    18 | React 18/19, aliases, importer edges and snapshots |
| Yarn Classic v1   |       13 |    16 | React 18/19, npm aliases, transitive dependencies and workspace hoisting |
| Yarn Berry metadata v4/v6/v8 | 3 each | 3 each | Workspace identities and optional-peer behavior; registry package resolution is covered by bounded parser fixtures, not manager-generated registry archives |

These are resolver fixtures, not proof of artifact authenticity. Every
lock-declared registry digest remains `declared-not-verified` until a separate
artifact verification step checks the downloaded bytes.
