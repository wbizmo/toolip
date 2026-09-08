# Changelog

All notable changes to Toolip are documented in this file.

The format follows Keep a Changelog principles, and Toolip uses semantic versioning.

## Unreleased

## 2.2.1 - 2026-09-08

### Changed

- Dependency-health analysis now consumes the canonical resolved npm lockfile inventory used by OSV, dependency trees, SBOM generation, install-script analysis, and reachability.
- Package-health registry work and score penalties are deduplicated by exact `name@version` while `totalDependencies` continues to represent the complete installed dependency graph.
- Dependency finding IDs now include the resolved package version so different installed versions of one package cannot collide.
- npm workspace link entries are followed to their resolved workspace package identity and exact version.
- npm trusted publishing can run from verified `main` release commits as well as an explicitly authorized manual dispatch, and remains idempotent when the version already exists.

### Fixed

- Fixed `toolip scan`, `toolip doctor`, and `toolip score` analyzing only direct `package.json` declarations for deprecated, outdated, no-maintainer, stale, and risk signals while vulnerability analysis used the full resolved transitive graph.
- Fixed manifest ranges and non-version specifiers such as caret ranges, `workspace:*`, npm aliases, tags such as `latest`, and Git specifiers being treated as installed versions during dependency-health analysis.
- Fixed transitive deprecated, outdated, stale, and no-maintainer packages being invisible to dependency-health findings and scoring.
- Fixed `totalDependencies` reporting only direct manifest dependencies instead of the full resolved installed dependency graph.
- Fixed multiple resolved versions of the same package producing colliding dependency finding IDs.
- Fixed npm workspace link records being skipped by the canonical dependency graph when the linked `node_modules` entry carried no version of its own.
- Added an explicit warning when multiple supported package-manager lockfiles coexist instead of silently applying `pnpm > yarn > npm` precedence.

### Security

- Clarified that raw SHA-256 secret fingerprints are stable correlation/redaction metadata, not a password hash, commitment, authentication primitive, or security boundary; low-entropy values may be guessable and fingerprints should remain sensitive report metadata.
- Added regression coverage for deep transitive dependency health, exact resolved versions, duplicate installed versions, npm workspace links, and package-manager lockfile conflicts.

## 2.2.0 - 2026-09-07

### Added

- Measurement-aware security scoring states so unavailable, failed, timed-out, or cancelled analysis is never represented as a perfect score.
- Canonical MCP workspace authorization using resolved real paths and symlink-safe containment.
- Shared project context and scan budgets for bounded repository analysis.
- Hard analyzer deadlines, explicit execution status, failure isolation, deterministic ordering, and bounded provider concurrency.
- Stable per-occurrence secret finding identity and fingerprint-based redaction.
- Explicit synthetic-secret fixture markers instead of blanket test-file severity downgrades.
- Vault shell/JSON export formats with safe POSIX shell quoting.
- Vault mutation locking, schema validation, permission repair, and atomic same-directory replacement.
- Staged-file pre-commit analysis with explicit full-scan mode.
- Package-manager-aware dependency-upgrade pull requests using isolated Git worktrees.
- Compiler-backed static quality checks and production dependency audit gating.
- Official Vitest V8 coverage gates for security-critical modules.
- Node.js 22 and 24 CI coverage across Ubuntu, macOS, and Windows.
- Least-privilege GitHub Actions release/publish automation.

### Changed

- Consolidated internal security analysis onto one canonical `Finding` contract; legacy report compatibility now lives at serialization boundaries.
- Replaced hoisting-based direct-dependency classification with one resolved lockfile dependency inventory/graph.
- `toolip tree`, install-script analysis, SBOM relationships, reachability, and dependency intelligence now reuse the same package graph.
- Project discovery is reused instead of repeatedly walking the repository within one command.
- Source analyzers use bounded reads and explicit skipped/failed accounting.
- Git-history analysis now streams patch output instead of buffering the full history in memory.
- Dockerfile matching now uses one indexed pass and preserves correct line numbers for repeated lines.
- OSV work is deduplicated by exact package/version and correlated through indexed lookups.
- Removed the misleading process-local six-hour vulnerability cache from one-shot CLI execution.
- Pre-commit defaults to staged changes instead of rescanning unrelated historical findings.
- Git hook installation preserves existing hook logic instead of overwriting `.git/hooks/pre-commit`.
- `upgrade-pr` no longer mutates or switches the caller's current worktree.
- Watch mode reports callback failures and continues monitoring.
- Windows watch mode now uses a managed non-recursive directory-watcher tree instead of the Node 24/libuv recursive watcher path.
- License facts now come from deps.dev for exact resolved direct-dependency versions instead of a hard-coded package map.
- CLI composition moved into reusable `createProgram()`; `src/index.ts` is now a minimal executable entrypoint.
- Replaced source-string command-registration tests with behavioral Commander command-tree coverage.
- Declared supported Node engines as `>=22 <25`.
- Upgraded GitHub Actions runtime majors and refreshed compatible transitive dependency versions.

### Fixed

- Prevented security score dimensions that were never measured from defaulting to `100/100`.
- Prevented the dependency score from assuming a zero vulnerability penalty when vulnerability analysis was not executed.
- Corrected npm-hoisted transitive packages being reported as root direct dependencies.
- Corrected nested duplicate package versions being skipped or inspected through the wrong `node_modules` path.
- Replaced placeholder dependency-tree children with real resolved edges.
- Removed repeated full repository traversals from Doctor, pre-commit, and analyzer paths.
- Corrected `filesScanned` so unreadable/skipped files are not counted as successfully analyzed.
- Prevented one analyzer failure or ignored cancellation signal from aborting/locking the entire analyzer run.
- Prevented same-pattern multiple secrets in one file from collapsing into one finding.
- Prevented raw/short secret evidence and token fragments from appearing in reports by default.
- Prevented real credentials in test files from being automatically downgraded solely because of path naming.
- Prevented vault shell exports from allowing `$`, command substitution, backticks, or quoting rules to alter secret values when sourced.
- Prevented concurrent vault read-modify-write operations from losing updates.
- Prevented interrupted vault writes from replacing the primary vault with partial content.
- Prevented MCP `..` traversal and symlink escapes outside approved workspace roots.
- Prevented hook installation from clobbering Husky/custom pre-commit logic.
- Prevented failed dependency-upgrade PR creation from leaving users on a new branch with modified files.
- Prevented watch callback failures from surfacing as unhandled rejections.
- Prevented Node 24 on Windows from hitting the native recursive `fs.watch` assertion in Toolip watch mode.
- Removed fixable production dependency advisories; runtime npm audit is clean in the v2.2.0 release candidate.

### Security

- Strengthened workspace authorization at the MCP trust boundary.
- Strengthened secret redaction and fixture handling in current-tree and Git-history analysis.
- Hardened local vault persistence and shell export semantics.
- Added a production dependency audit gate to `npm run verify` and release checks.
- Added minimum security-critical coverage floors of 75% statements/lines, 65% branches, and 85% functions.
- Kept npm publishing separate from ordinary CI and prepared trusted-publishing/OIDC release authorization.
- Continued release verification against the exact npm tarball that users install.

## 2.1.1 - 2026-07-13

### Fixed

- Unified `toolip scan` and `toolip score` on the same canonical dependency-health calculation.
- Removed the remaining finding-based scoring path from the `scan` command.
- Ensured both commands report the same dependency-health score for the same project state.
- Centralized dependency-health calculation inside `scanDependencies()`.
- Added regression coverage preventing the two commands from drifting onto separate scoring paths again.

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
* Structured terminal and JSON output.

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
