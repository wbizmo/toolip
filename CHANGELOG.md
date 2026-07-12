# Changelog

All notable changes to Toolip are documented in this file.

The format follows Keep a Changelog principles, and Toolip uses semantic versioning.

## Unreleased

### Added

- Dockerfile and container build scanning.
- npm and pnpm workspace discovery.
- Remote public GitHub repository auditing through `gh`.
- Tested dependency-upgrade pull requests.
- Security-relevant Git diff summaries.
- Static HTML security reports.
- Real-time local watch mode.
- Deterministic security announcement generation.
- Read-only Toolip MCP server.
- Local security history with score and finding trends.
- Versioned `toolip.config.json` policy controls.
- deps.dev package metadata, dependency graph, provenance, and attestation intelligence.
- Dependency confusion detection for internal-looking npm dependencies.
- Redacted full Git-history secret scanning.
- TypeScript Compiler API security analysis for JavaScript and TypeScript source files.
- `toolip ast-scan` with structured JSON output and configurable failure thresholds.
- AST resolution for named, aliased, namespace, and CommonJS child-process imports.
- AST detection for `eval()` and the dynamic `Function` constructor.
- Shared analyzer, finding, rule, report, and cache contracts for Toolip v2.
- Bounded analyzer orchestration with timeout and cancellation support.
- Cross-platform continuous integration.
- Release candidate verification from the packed npm artifact.
- Architecture, engineering, contribution, security, and release documentation.

### Changed

- Security doctor dangerous-code checks now use AST analysis instead of raw `exec(` string matching.
- TypeScript is now a runtime dependency because the published CLI performs AST parsing.
- Release verification now validates the exact tarball users will install.
- `package.json` remains the sole source of version truth.
- npm package contents are restricted to the compiled CLI and required documentation.

### Security

- Releases are blocked when the executable, README, license, shebang, or version synchronization is invalid.
