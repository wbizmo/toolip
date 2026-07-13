# Changelog

All notable changes to Toolip are documented in this file.

The format follows Keep a Changelog principles, and Toolip uses semantic versioning.

## Unreleased

## 2.1.0 - 2026-07-13

### Changed

- Reworked dependency-health scoring to distinguish disclosed vulnerabilities from maintenance and freshness signals.
- Added version-aware penalties for major, minor, and patch-level dependency updates.
- Capped outdated-dependency penalties so maintenance lag alone cannot collapse dependency health to zero.
- Reduced patch-update penalties to a minimal fractional weight.
- Added a dependency-health score breakdown for vulnerability, deprecation, maintenance, and freshness penalties.
- Added structured JSON output to `toolip score`.

### Fixed

- Prevented projects with zero known vulnerabilities from receiving a dependency-health score of zero solely because several packages were outdated.
- Prevented each outdated dependency from being treated like an independent medium-severity security vulnerability.
- Added regression coverage for the exact 11-outdated-dependency failure reproduced against Toolip itself.



## 2.0.1 - 2026-07-13

### Fixed

* Classified password-like values committed inside test files as low-severity potential test fixtures during Git-history scanning.
* Preserved historical source file paths in Git-history findings.
* Applied medium confidence and fixture-specific remediation guidance to historical test fixtures.
* Kept genuine credentials outside test files at their original high or critical severity.
* Preserved redacted evidence and secret fingerprints for historical secret findings.

## 2.0.0 - 2026-07-13

### Added

* OSV.dev vulnerability matching for resolved npm dependencies.
* Package reachability analysis using JavaScript and TypeScript imports.
* Install-script analysis for network access, shell execution, filesystem changes, obfuscation, and environment access.
* CycloneDX 1.5 and SPDX 2.3 SBOM generation.
* TypeScript Compiler API security analysis for JavaScript and TypeScript source files.
* `toolip ast-scan` with structured JSON output.
* AST resolution for named, aliased, namespace, and CommonJS child-process imports.
* AST detection for `eval()`, dynamic `Function` construction, `child_process.exec()`, and `execSync()`.
* Local security history with score and finding trends.
* Versioned `toolip.config.json` project configuration.
* Rule enablement, severity overrides, path-specific policy, suppressions, and provider configuration.
* deps.dev package metadata, dependency graph, license, advisory, provenance, and attestation intelligence.
* Dependency-confusion detection for internal-looking npm package names.
* Redacted Git-history secret scanning.
* Dockerfile and container build scanning.
* npm and pnpm workspace discovery.
* Remote public GitHub repository auditing through the authenticated `gh` CLI.
* Tested dependency-upgrade pull-request generation.
* Security-relevant Git diff summaries.
* Static HTML security report generation.
* Real-time local watch mode.
* Deterministic security announcement generation.
* Read-only Toolip MCP server.
* Shared analyzer, finding, rule, report, and cache contracts.
* Bounded analyzer orchestration with timeout and cancellation support.
* Cross-platform continuous integration.
* Release-candidate verification against the packed npm artifact.
* Architecture, engineering, contribution, security, and release documentation.

### Changed

* Replaced dangerous-code string matching with AST-based analysis.
* Distinguished `RegExp.exec()` from resolved `child_process.exec()` calls.
* Restricted dangerous-code analysis to executable JavaScript and TypeScript source files.
* Prevented JSON reports containing previous findings from being rescanned as executable code.
* Downgraded password-like values inside test files to low-severity potential fixtures.
* Moved TypeScript into runtime dependencies because the published CLI performs AST parsing.
* Made `package.json` the single source of truth for the Toolip version.
* Restricted npm package contents to the compiled CLI and required documentation.
* Expanded release verification to validate the exact tarball users install.
* Added isolated tarball installation and packed CLI smoke tests to the release process.

### Security

* Blocked releases when the compiled executable is missing.
* Blocked releases when README, LICENSE, CLI shebang, or version synchronization is invalid.
* Added npm tarball inspection before publication.
* Added isolated packed-package installation before publication.
* Added checks preventing shell files, logs, tests, temporary tarballs, and development files from entering npm releases.
* Redacted historical secret evidence while retaining deterministic fingerprints.

## 1.0.7 - 2026-07-11

### Fixed

* Restored the complete compiled CLI after v1.0.6 was published without `dist/src`.
* Added package-content verification before publication.
* Added packed-tarball installation and CLI execution checks.
* Removed the hardcoded Toolip version and resolved it from `package.json`.
* Fixed the false positive that treated `RegExp.exec()` as `child_process.exec()`.
* Prevented JSON reports from being scanned as executable source code.
* Downgraded password-like test fixtures to low severity.
* Preserved detection of genuine shell execution calls.

### Changed

* Added a mandatory `prepack` verification process.
* Added clean build verification before packaging.
* Added CLI version, self-test, and help checks against the packed artifact.
* Added explicit npm package file allowlisting.

## 1.0.6

### Known Issue

* Published npm package omitted the compiled `dist/src` CLI output.
* Fresh installations did not provide a working `toolip` executable.
* This version was deprecated and superseded by v1.0.7.

## 1.0.5

### Added

* Project profiling and dependency scanning.
* Security doctor and scorecard commands.
* npm package inspection and comparison.
* License inventory and package-alternative analysis.
* Dependency tree summaries.
* Encrypted local Toolip Vault.
* Git safety auditing.
* Pre-commit security checks and Git hook installation.
* Secure development learning commands.
* Structured reports and JSON output.

### Known Issues

* CLI version output still reported v1.0.3 because version metadata was duplicated.
* Dangerous-code detection could mistake `RegExp.exec()` for shell execution.
* Test fixture passwords could be reported too aggressively.

## 1.0.4

### Changed

* Added README documentation to the npm package.
* Improved package metadata and npm presentation.

## 1.0.3

### Fixed

* Corrected CLI help and version handling so Commander help and version exits no longer printed false error messages.
* Updated Toolip’s internal version metadata.
* Verified global npm installation, `self-test`, help output, and version output.

### Changed

* Improved CLI error handling for expected Commander exits.
* Added regression coverage for CLI version metadata.

## 1.0.2

### Fixed

* Relaxed the CLI binary path assertion to accept npm-normalized package paths.
* Restored the full passing test suite after npm normalized the `bin` path.

## 1.0.1

### Fixed

* Improved handling of `toolip --help` and `toolip --version`.
* Prevented expected Commander exits from being reported as Toolip failures.

### Known Issue

* Internal version output could still report v1.0.0 because the version value was hardcoded separately from `package.json`.

## 1.0.0

### Added

* Initial public release of Toolip.
* Project self-test and diagnostics.
* Project framework and tooling profiling.
* Dependency and security hygiene scanning.
* Security doctor audits.
* Security scorecards.
* npm package inspection and comparison.
* License analysis.
* Package alternative suggestions.
* Dependency tree inspection.
* Encrypted local secrets management using Toolip Vault.
* Git safety auditing.
* Pre-commit security checks.
* Git hook installation.
* Secure development learning content.
* Structured terminal and JSON output.

### Security

* Added detection for token-like secrets, private keys, hardcoded passwords, API keys, and JWT secrets.
* Added checks for dangerous code patterns and weak security configuration.
* Added encrypted local secret storage.
