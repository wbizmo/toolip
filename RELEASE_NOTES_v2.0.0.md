# Toolip v2.0.0

Toolip v2.0.0 turns the original developer security CLI into a broader local-first security platform for JavaScript and TypeScript projects.

## Vulnerability and dependency intelligence

- Added OSV.dev matching for disclosed vulnerabilities against exact npm package versions.
- Added deps.dev package metadata, dependency graph, provenance, attestation, license, and advisory intelligence.
- Added package reachability evidence based on JavaScript and TypeScript imports.
- Added dependency-confusion checks for internal-looking package names that collide with public npm packages.
- Added install-script analysis for suspicious network, shell, filesystem, obfuscation, and environment-access behavior.
- Added CycloneDX 1.5 and SPDX 2.3 SBOM generation.

## Source and application security

- Added TypeScript Compiler API analysis for supported dangerous-code patterns.
- Distinguished `RegExp.exec()` from resolved `child_process.exec()` calls.
- Added stable rule IDs, normalized findings, confidence levels, evidence, remediation, and machine-readable metadata.
- Added configurable rule severity, path policy, suppressions, provider settings, and history retention through `toolip.config.json`.

## Git, repository, and delivery security

- Added full Git-history secret scanning with redacted evidence and fingerprints.
- Added security-relevant diffs between Git revisions.
- Added remote public GitHub repository auditing through the authenticated `gh` CLI.
- Added tested dependency-upgrade pull-request generation.
- Added Dockerfile checks for root execution, embedded secrets, unpinned images, remote downloads, and package cleanup.
- Added npm and pnpm monorepo workspace discovery.

## Developer workflows

- Added local security history and score trends.
- Added static HTML security report generation.
- Added real-time watch mode.
- Added deterministic local security announcement generation.
- Added a read-only MCP server for security doctor, SBOM, and Git diff operations.

## Release engineering

- `package.json` remains the single source of version truth.
- Releases are checked through typechecking, the complete test suite, a clean production build, package-content validation, npm tarball inspection, isolated tarball installation, CLI version verification, self-test, and help output.
- The release process blocks publication when the compiled CLI, README, license, executable shebang, version synchronization, or required package contents are missing.

## Installation

```bash
npm install -g toolip@2.0.0
```

## Verification

```bash
toolip --version
toolip self-test
toolip --help
```

Built by Ashibuogwu Williams (`wbizmo`).
