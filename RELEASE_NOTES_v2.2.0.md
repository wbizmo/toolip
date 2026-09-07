# Toolip v2.2.0 — Security Hardening & Release Trust

Toolip v2.2.0 is a broad hardening release focused on one goal: make every security claim, filesystem boundary, dependency identity, execution path, and release artifact more trustworthy while reducing unnecessary work inside the CLI.

This release follows a repository-wide security, correctness, first-principles engineering, and efficiency audit. The fixes were implemented as isolated issues/PRs, validated against the complete cross-platform CI matrix, and consolidated into the v2.2.0 release.

## Security boundaries

### MCP workspace containment

MCP tools that accept a project root now enforce the configured workspace boundary using canonical filesystem paths.

- requested roots are resolved through `realpath()` before authorization
- `..` traversal outside an approved workspace is rejected
- symlink escapes are rejected after canonical resolution
- authorization uses path containment rather than unsafe string-prefix checks
- the MCP surface remains read-only and does not expose arbitrary shell execution

### Secret evidence and detection

Secret scanning now treats findings as security facts rather than display strings.

- every supported same-rule secret occurrence in a file can produce its own finding
- finding identity is stable per occurrence instead of colliding at rule/file level
- raw token fragments are no longer exposed as report evidence by default
- deterministic fingerprints can correlate findings without publishing the secret
- test files are no longer blanket-downgraded merely because of their path
- explicit synthetic fixtures can still be marked intentionally
- Git-history scanning applies the same safer redaction/fixture model

### Toolip Vault

Vault persistence and export were hardened without breaking the existing encrypted format.

- POSIX shell export now uses safe single-quote encoding
- `$`, `$(...)`, backticks, backslashes, quotes, spaces, and newlines remain literal when sourced
- shell environment-variable key validation occurs at export time, preserving JSON/storage compatibility
- vault writes are serialized with a local lock to prevent lost updates
- encrypted updates use a temporary same-directory file followed by atomic rename
- valid older vaults have restrictive POSIX permissions repaired when read or written
- malformed JSON/schema/base64/decrypted payloads fail through controlled Toolip errors
- the current AES-256-GCM + `scrypt` version-1 encrypted format remains compatible

## Correctness

### Truthful security scoring

The scorecard no longer treats missing analysis as perfect security.

Toolip now distinguishes measured dimensions from unavailable, failed, timed-out, or cancelled analysis. An analyzer/provider that did not produce evidence cannot silently turn into `100/100`.

Dependency scoring is also based on actual vulnerability analysis rather than assuming a zero vulnerability penalty when OSV was never consulted.

### One canonical finding model

Toolip now uses one internal normalized `Finding` contract for security analysis. Legacy report compatibility is handled at serialization/output boundaries instead of maintaining a second security fact model throughout the codebase.

This reduces conversion paths and prevents different commands from interpreting the same security fact differently.

### Correct resolved dependency graph

The dependency model now represents the lockfile rather than npm's physical hoisting layout.

- direct dependencies come from root manifest/lock declarations
- a transitive dependency hoisted to root `node_modules` is no longer misclassified as direct
- exact package installation paths are retained
- nested/duplicate versions remain distinguishable
- dependency edges are resolved using nearest `node_modules` semantics
- `toolip tree` now represents real resolved relationships instead of placeholder empty children
- install-script analysis reads the exact resolved package instance
- CycloneDX/SPDX relationships and dependency analysis reuse the same graph

## Execution reliability and scale

### Single project discovery context

Repository discovery is now reused instead of repeatedly walking the entire tree inside one command.

This removes duplicated work from Doctor, pre-commit, AST, reachability, Docker, and other analysis paths.

Toolip also tracks discovered/scanned/skipped/failed file counts accurately rather than counting unreadable files as successfully scanned.

### Scan budgets and bounded reads

Source analyzers no longer blindly read arbitrary files in full.

- file-count and byte budgets bound repository work
- oversized/binary-like files are skipped intentionally
- file reads are bounded
- analyzers can reuse the shared project inventory
- Git-history analysis processes output incrementally instead of buffering the full patch history
- Dockerfile analysis uses a single indexed pass, preserving correct line numbers for repeated lines

### AnalyzerRunner hardening

The analyzer execution layer now guarantees more than a cooperative `AbortSignal`.

- hard deadlines terminate the runner's wait even when an analyzer ignores cancellation
- sibling analyzer failures do not discard successful results
- timeout/failure/cancellation state is explicit
- results retain deterministic input order
- provider/package fan-out uses bounded concurrency
- OSV requests are deduplicated by exact package/version
- vulnerability correlation uses indexed lookups instead of repeated linear scans
- the misleading process-local six-hour CLI cache was removed rather than pretending it survived process exit

## Safer Git/developer workflows

### Non-destructive hooks

`toolip hook install` no longer overwrites an existing pre-commit hook. Toolip preserves existing hook logic and manages its own integration explicitly.

### Staged pre-commit analysis

Pre-commit mode scans the staged change set by default. Existing unrelated repository findings do not block a commit unless the user explicitly requests a full scan.

### Transactional upgrade PRs

`toolip upgrade-pr` now performs mutable upgrade/test operations in an isolated temporary Git worktree.

- the user's current branch is not switched
- dirty files in the caller's worktree are preserved
- failures clean up the temporary worktree
- invalid versions are rejected before mutation
- branch collisions are handled deliberately
- npm, pnpm, and Yarn projects use package-manager-aware lockfile update behavior

### Resilient watch mode

Watch mode now reports analysis callback failures and continues monitoring instead of producing an unhandled rejection.

Node 24 on Windows also exposed a native libuv assertion in recursive `fs.watch`. Toolip now uses a managed non-recursive directory-watcher tree on Windows instead of depending on that crashing recursive path, while retaining debounce, queueing, ignore rules, and recovery semantics.

## Package metadata and provider trust

License facts now come from deps.dev for the exact resolved direct-dependency version instead of a hard-coded map containing only a handful of package names.

Provider failures are explicit. Toolip does not silently substitute guessed license facts when authoritative metadata is unavailable.

## Testing and engineering quality

v2.2.0 removes low-value tests that inspected `src/index.ts` for registration strings and replaces them with behavioral Commander command-tree assertions.

The CLI entrypoint is now intentionally small; program composition lives in a reusable `createProgram()` function.

The verification pipeline adds:

- Node.js runtime declaration: `>=22 <25`
- Node 22 and Node 24 CI coverage
- Ubuntu, macOS, and Windows execution for every supported Node major
- compiler-backed static quality checks (`noUnusedLocals`, `noUnusedParameters`, `noImplicitReturns`, `noFallthroughCasesInSwitch`)
- production dependency auditing at high severity
- official Vitest V8 coverage for security-critical modules
- minimum security-critical coverage floors of 75% statements/lines, 65% branches, and 85% functions

During the release hardening work, npm's production graph exposed transitive advisories. The lockfile was refreshed within compatible dependency ranges and the release verification now reports zero npm vulnerabilities.

## Release trust

Toolip continues to verify the package users actually install, not merely the source tree.

`npm run release:check` validates quality gates, runtime dependency audit, tests/coverage, a clean build, required npm package contents, the executable shebang, packed tarball installation, and packaged CLI execution.

v2.2.0 also introduces a least-privilege GitHub Actions release path:

- normal CI has read-only repository permissions
- npm publishing is separate from CI
- the preferred publish flow uses npm trusted publishing/OIDC rather than exposing a long-lived token to build jobs
- the npm publish job is manual, restricted to `main`, version-checked, confirmation-gated, and compatible with a protected `npm-release` environment
- GitHub release/tag creation is performed from the verified main release commit and the checked-in release notes

## Compatibility

- Toolip v2.2.0 supports Node.js 22 and 24.
- Existing valid Toolip Vault v1 files remain supported.
- Existing report consumers retain the legacy serialized report shape where compatibility is required even though the internal finding model is unified.
- Remote GitHub operations remain opt-in and use the user's own authorization.

## Verification

The release candidate is required to pass:

- changelog verification
- compiler-backed quality checks
- production `npm audit` gate
- complete test suite
- security-critical V8 coverage thresholds
- Node 22 and 24 on Ubuntu
- Node 22 and 24 on macOS
- Node 22 and 24 on Windows
- clean production build
- built-package verification
- npm tarball content verification
- isolated tarball installation
- packaged `toolip --version`
- packaged `toolip self-test`
- packaged `toolip --help`

## Install

```bash
npm install -g toolip@2.2.0
```

Then verify:

```bash
toolip --version
toolip self-test
toolip --help
```

Built by Ashibuogwu Williams (`wbizmo`).
