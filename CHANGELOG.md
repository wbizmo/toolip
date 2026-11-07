# Changelog

All notable changes to Toolip are documented in this file.

The format follows Keep a Changelog principles, and Toolip uses semantic versioning.

## Unreleased

- Avoid copying source expressions into AST evidence, omit install-script command text, and redact supported credential patterns in analyzer output, errors, reports and MCP output; remove low-entropy secret hashes from public finding summaries and identities.
- Scan bounded readable text files including credential dotfiles such as `.npmrc`; source comments no longer suppress secret findings, and fixture suppression requires caller-owned policy with optional expiry.
- Trace Stage A GitHub Actions block-form commands and working directories into exact npm/pnpm/Yarn workspace manifests and package-relative script targets; follow VS Code automatic task dependencies, reject malformed run scalars, and mark unresolved workspace/task references incomplete.
- Serialize vault and history mutations across processes, reject unsafe local-state symlinks and foreign-owned POSIX paths with actionable vault-read errors, atomically flush replacements, and reclaim lock leases left by terminated owners after lease expiry.
- Reconcile security-watch directories after filename-less events and directory replacement so recreated subtrees remain monitored; keep the recursive watcher on Linux and use reconciled per-directory watches on macOS and Windows.
- Set the package homepage metadata to `https://www.zivoralabs.xyz/open-source/toolip/`.
- Add signed declarative literal-rule packs to `doctor` and `scan`, with explicit unsigned local override, redacted evidence, expiry and bounded output; executable third-party plugins remain disabled pending OS-level isolation.
- Add an opt-in read-only GitHub App runner with signed webhooks, delivery deduplication, allowlisted schedules, and single-repository `checks:write` status publication.
- Require explicit `--allow-project-tests` authorization before an upgrade worktree runs repository-defined test commands; dependency installs continue to skip lifecycle scripts.
- Add deterministic randomized line-location fuzzing and full offline scorecard benchmarks at 1k, 10k and 50k generated repository files; retain the 1m release run for final release validation.
- Generate detached DSSE/in-toto signatures for CycloneDX/SPDX SBOMs and verify exact canonical subjects, trusted key/project identities, signatures and freshness; signed reports and SBOM attestations bind a bounded digest of package metadata and the complete runtime module tree, with optional `--scanner-artifact-sha256` enforcement.
- Revalidate the live pull request base/head/merge identity before workflow-run CI begins, rejecting stale Stage A results after branch updates or force-pushes.
- Apply current-maintainer-reviewed Stage A exceptions to exact-tree npm artifact findings and coverage reasons while retaining mandatory artifact-count and signature-audit verification.
- Freeze the canonical MCP workspace boundary and allowlist so caller mutation cannot change the roots trusted by a running server.
- Bind Stage A tarball inspection to exact npm lockfile artifact identity, including aliased package names; a valid digest cannot mask a mismatched embedded name or version.
- Require exact-tree maintainer review for changes to the Stage A scanner, artifact verifiers, runtime/workflow trust checks, CODEOWNERS and gated workflows before the new implementation can reach Stage B.
- Persist GitHub App delivery replay IDs and installation suspension state in a bounded private journal, and abort queued/active scans when an installation is suspended.
- Report request-derived shell command flows through `exec`/`execSync` and explicit `shell: true` APIs, while keeping default argument-array execution distinct and flagging dynamic child-process method selection as uncertain.
- Track sensitive credential data to bounded filesystem, browser-storage, IndexedDB and database write sinks; storage candidates remain medium severity and low confidence, with source names and values redacted.
- Extend same-handler BOLA candidates through request-parameter and authenticated tenant aliases, shorthand and nested ownership predicates, while excluding ambiguous shadowed/reassigned identities and preserving low-confidence review status.
- Propagate MCP cancellation through CycloneDX/SPDX serialization and prevent queued handlers from starting after an immediate client abort; large SBOM lists yield to the event loop and stop when cancelled or timed out.
- Compare exact base/head dependency package instances for PR lockfile changes, and keep the diff result incomplete until advisory impacts are recalculated by a full scan.
- Generate bounded safe inline review records for introduced PR findings on changed lines, without embedding source, evidence or provider text.
- Add an opt-in bounded offline scorecard soak runner for snapshot invalidation, cache reuse, coverage and RSS ceilings; retain the million-file benchmark for final release validation.
- Add explicit opt-in Code Scanning SARIF upload to the composite GitHub Action with an immutable uploader pin and fork-PR guard.
- Follow bounded project-relative pip requirement/constraint includes; constraints alone no longer create installed dependency identities.
- Resolve supported Python dependency specifiers only to unique exact lockfile instances, preserving the range as edge metadata rather than treating it as an installed version.
- Propagate custom or unverified pip index configuration across included requirements files, keep their hashes from implying public PyPI provenance, and withhold those identities from public OSV lookups.
- Follow common Node, Python, Ruby, Perl, PHP, shell, PowerShell and Windows command-launcher references in bounded malicious-content chains, including disguised target suffixes; refresh the trusted Stage A scanner digest.
- Key cached AST findings by each file's resolved transitive import closure, so helper edits invalidate dependent files while unrelated source and data files retain reusable results.
- Keep Go `go.mod` requirements unknown until Minimal Version Selection is resolved; add explicit bounded Go-tool resolution against captured metadata with fresh checksum-database verification for scan and SBOM.
- Scan captured local Terraform modules and report remote, dynamic, missing, or escaping module sources as incomplete infrastructure coverage.
- Omit matched Dockerfile instruction text from findings entirely; secret values no longer depend on a name-based evidence redactor.
- Keep signature-verified WASM analyzer bytes in module-private storage so callers cannot mutate executable code after verification.
- Preserve a pushed upgrade branch when `gh pr create` fails ambiguously; delete it only after GitHub confirms no pull request references that head.
- Keep Composer branch labels such as `dev-main` in the graph with unknown resolution confidence instead of treating them as exact released versions.
- Omit matched Dockerfile instruction text from findings entirely; secret values no longer depend on a name-based evidence redactor.

### Security

- File scans now bind reads to discovery-time file identity, preserve nanosecond modification/change times, use nonblocking opens on POSIX, use initialized bounded buffers, loop until the exact file length is read, hash completed content, and mark changed, escaped, short, or growing files incomplete instead of analyzing partial bytes (#47, #53). Filesystem-backed findings include the exact source digest plus JSON-safe discovery and verified-read identity metadata. Discovery reports incomplete scans for unignored symbolic directories, missing symlink targets, or entries it cannot inspect, applies directory-only ignore rules to symlink targets, filters ignored paths before metadata reads, limits concurrent inspection, and applies `maxFiles` only to non-ignored files; projects with ignored manifests retain profile metadata through a separate checked read. `docker-scan` reports failed or partial coverage when discovered Dockerfiles change before analysis.
- Added deterministic MCP SDK regressions for malformed/oversized tool arguments and client abort propagation to active server handlers (#50).
- Dependency advisories resolved for `@modelcontextprotocol/sdk` (1.32.2), `zod` (4.6.7), `pacote` (22.0.1), `vitest`/`@vitest/coverage-v8` (5.1.0) and transitive `proxy-addr`, `undici`, `qs`, `hono`, `ip-address`, `fast-uri`, `vite`, `source-map-js`, `body-parser`, `brace-expansion`, `glob` (14.0.3) and `minimatch` (11.0.4). `npm audit` reports 0 vulnerabilities.

### Fixed

- `ast-scan`, `install-scripts`, `reachability` and `vulnerabilities` no longer print a clean-success message and exit 0 when the analyzer failed, timed out or skipped inputs; results carry a `complete|partial|failed` state with coverage, and exit codes 0/2/3/4 are documented (#35, #34). See `docs/ANALYSIS-STATUS.md`.
- Analyzer timeouts are enforceable: the AST analyzer runs in a worker thread that is terminated on deadline or cancellation, and non-cooperative in-process analyzers are reported `unresponsive` (#27).
- `doctor`, `scan` and `pre-commit` report scanned/skipped/failed coverage and fail closed when nothing could be scanned; `pre-commit` blocks partial scans unless `--no-fail-on-incomplete` (#34).
- Registry lookups run under a scan budget (deadline, cancellation, request timeout, concurrency cap, bounded retry with `Retry-After`); malformed responses and unmeasured dependencies are never scored as healthy (#48).
- `toolip diff` and the MCP `toolip_diff` tool no longer pass `${base}..${head}` to Git as one argument; a value such as `--output=/path` could create a file. Revisions are validated, resolved to commit IDs and rejected with typed errors when unsafe (#45). Ranges and expressions like `HEAD~1` are no longer accepted; use a commit ID.
- `toolip pre-commit` now scans the staged blobs from the Git object database instead of working-tree files, so a clean worktree can no longer hide a staged secret and an unstaged secret no longer blocks a safe commit; Git read failures and unmerged entries fail closed (#26).
- `toolip hook install` installs into Git's effective hooks directory (`core.hooksPath`, linked worktrees), places the block ahead of user logic, refuses non-shell hooks and never downloads packages (#41).
- `toolip git-audit` asks Git whether files are ignored and reports tracked sensitive files separately; outside a Git work tree the status is reported as unknown (#42).

### Changed

- Minimum supported Node.js is now 22.23.4 or 24.22.1 (October 2026 security releases; 24.22.2+ recommended). The CLI refuses to scan on unpatched or unsupported runtimes unless `TOOLIP_ALLOW_UNPATCHED_NODE=1` is set, `self-test` reports the runtime, and CI/`verify-node` enforce the floor in `security/runtime-floors.json`. See `docs/RUNTIME-AND-DEPENDENCY-SECURITY.md`.
- CodeQL now runs from one workflow (`codeql.yml`) on PRs, `main` and weekly so PR alerts compare with main's baseline; all CI installs use `npm ci --ignore-scripts`, enforced by `verify-workflows.mjs`.
- Runtime enforcement moved from argv sniffing to a Commander `preAction` guard, closing a bypass where `--help`, `-h` or `self-test` could appear as an option value; the lockfile gate now fails on malformed advisory policies, matches policy against the location, `name` field (npm aliases) and registry URL name, requires complete SHA-512/384 digests, and fails closed on missing/invalid versions for advisory-listed packages and a missing `lockfileVersion`.
- New `audit.yml` runs the full dependency audit and registry signature check on pushes to `main` and weekly.
- Lockfile gate now also checks the lockfile root version/name and fails if any package listed in `security/advisory-floors.json` is installed in a vulnerable range; an MCP stdio smoke test covers the SDK 1.32.2 upgrade.
- CI now enforces Biome lint, Prettier formatting, workflow and lockfile policy, full dependency audit, Gitleaks, CodeQL and a Node 22/24 × Linux/macOS/Windows matrix; `publish.yml` and `github-release.yml` are manual-only and npm publishing uses OIDC trusted publishing instead of a stored token.

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
