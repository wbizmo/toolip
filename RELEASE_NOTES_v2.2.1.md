# Toolip v2.2.1 — Resolved Dependency Health

Toolip v2.2.1 is a correctness release that closes the dependency-graph split left in v2.2.0. Dependency health used by `toolip scan`, `toolip doctor`, and `toolip score` now consumes the same exact resolved npm lockfile inventory used by vulnerability analysis, dependency trees, SBOM generation, install-script analysis, and reachability.

## What changed

- Dependency health now analyzes the full resolved dependency inventory, including transitive packages, rather than only direct `package.json` declarations.
- Installed versions come from `package-lock.json` as exact resolved versions. Manifest ranges and specifiers such as `^1.2.3`, `workspace:*`, `latest`, npm aliases, and Git specifiers are no longer treated as installed versions for health analysis.
- Deprecated, outdated, stale, and no-maintainer signals can now surface from transitive dependencies and participate in the dependency-health score.
- Registry analysis is deduplicated by exact `name@version`, avoiding duplicate lookups and duplicate score penalties when the same resolved package version is installed at multiple paths.
- `totalDependencies` now reflects the full resolved installed dependency graph rather than the much smaller direct-dependency set.
- Dependency finding IDs include the resolved package version, preventing collisions when multiple versions of the same package are installed.
- npm workspace link entries are resolved to their exact workspace package identity and version instead of being skipped.

## Additional hardening

- Toolip now warns when multiple supported package-manager lockfiles coexist in a project instead of silently selecting one. The existing deterministic precedence remains `pnpm > yarn > npm`.
- Secret SHA-256 fingerprints are now explicitly documented as stable correlation/redaction metadata, not as a password hash, commitment, authentication primitive, or security boundary. Low-entropy values may be guessable from a fingerprint and the fingerprint should remain sensitive report metadata.
- The trusted npm publishing workflow can now publish a verified release commit from `main` automatically while remaining idempotent if that exact package version already exists.

## Why this matters

Before v2.2.1, Toolip's OSV vulnerability path and its dependency-maintenance scoring path could describe different dependency universes: vulnerabilities came from the complete resolved graph, while maintenance and freshness signals came from direct manifest declarations. That could hide important transitive deprecations or staleness and make dependency summaries misleadingly small.

v2.2.1 makes the release's dependency-graph guarantee true end to end: the security score and dependency findings now reason about resolved package versions from the same canonical inventory as the rest of Toolip's supply-chain analysis.

## Verification

The release adds regression coverage for:

- deep transitive dependency health
- exact resolved versions versus non-semver manifest specifiers
- multiple installed versions of one transitive package
- npm workspace link resolution
- multiple package-manager lockfile warnings

The release candidate must also pass Toolip's existing compiler-backed quality checks, production dependency audit, full Vitest suite, security-critical coverage gates, clean TypeScript build, packed-artifact verification, and isolated tarball installation checks before publication.
