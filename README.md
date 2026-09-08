# Toolip

**Local-first developer security for JavaScript and TypeScript projects.**

Toolip is a TypeScript-powered CLI for supply-chain security, dependency intelligence, secret detection, source-code security analysis, Git safety, SBOM generation, encrypted local secrets management, repository auditing, and secure development workflows.

It is designed to run close to the developer: from a terminal, pre-commit hook, CI job, watch process, static report, or read-only MCP integration. Toolip keeps project analysis local by default and makes remote operations explicit.

## Toolip v2.2.1

Toolip **v2.2.1** is a dependency-correctness release that closes the last split between Toolip's resolved vulnerability graph and the dependency-health path used by `scan`, `doctor`, and `score`.

Highlights include:

- one canonical resolved npm dependency inventory shared by vulnerability analysis, dependency health, tree, SBOM, install-script analysis, and reachability
- dependency-health analysis across direct and transitive packages instead of only direct `package.json` declarations
- exact lockfile versions for health analysis instead of coercing manifest ranges, tags, aliases, Git specifiers, or `workspace:*` into pretend installed versions
- package-health analysis deduplicated by exact `name@version`, with full installed-node counts retained in dependency summaries
- version-qualified dependency finding IDs so multiple installed versions of one package cannot collide
- npm workspace link resolution to exact workspace package identities and versions
- explicit warnings when multiple supported package-manager lockfiles coexist rather than silent precedence selection
- truthful security scoring that never treats an unmeasured dimension as a perfect score
- one canonical `Finding` contract across security analysis paths
- exact lockfile package-instance handling, including nested/duplicated installations
- one shared project context instead of repeated full repository discovery
- bounded source-file reads, binary/oversize protection, scan budgets, and truthful scanned/skipped/failed accounting
- hard analyzer deadlines, cancellation, partial-failure isolation, deterministic result ordering, and bounded network concurrency
- complete same-rule secret occurrence detection with stable per-occurrence identity
- safer secret evidence redaction and explicit fixture handling instead of blanket test-file downgrades
- MCP workspace containment using canonical filesystem paths and symlink-safe authorization
- shell-safe vault export plus locked, atomic vault persistence
- non-destructive Git hook installation and staged-file pre-commit scanning
- resilient watch mode with cross-platform filesystem handling
- transactional dependency-upgrade PRs executed in isolated Git worktrees
- npm, pnpm, and Yarn-aware upgrade handling
- authoritative deps.dev license metadata instead of a hard-coded package map
- behavioral CLI composition tests instead of source-string assertions
- Node.js 22 and 24 support across Linux, macOS, and Windows CI
- compiler-backed quality checks, production dependency auditing, and security-critical V8 coverage gates
- packed-artifact release verification and a least-privilege GitHub Actions release path

## Install

Toolip requires **Node.js 22 or 24**.

```bash
npm install -g toolip
```

Install this release explicitly:

```bash
npm install -g toolip@2.2.1
```

Verify the installation:

```bash
toolip --version
toolip self-test
toolip --help
```

## Quick Start

Profile the current project:

```bash
toolip profile
```

Run the main security checks:

```bash
toolip scan
toolip doctor
toolip score
```

Check exact resolved dependencies for disclosed vulnerabilities:

```bash
toolip vulnerabilities
```

Inspect source and dependency behavior:

```bash
toolip ast-scan
toolip reachability
toolip install-scripts
toolip dependency-confusion
```

Audit Git safety:

```bash
toolip git-audit
toolip git-history
toolip pre-commit
```

Generate an SBOM:

```bash
toolip sbom --format cyclonedx
toolip sbom --format spdx
```

Use the encrypted local vault:

```bash
toolip vault init
toolip vault set DATABASE_URL
toolip vault get DATABASE_URL
toolip vault list
toolip vault export --format shell
toolip vault export --format json
```

## Commands

| Command | Purpose |
| --- | --- |
| `toolip self-test` | Run Toolip installation diagnostics |
| `toolip profile` | Detect project technologies and structure |
| `toolip scan` | Analyze dependency and project risk |
| `toolip vulnerabilities` | Match resolved npm dependencies against OSV.dev |
| `toolip ast-scan` | Analyze JavaScript/TypeScript through the TypeScript Compiler API |
| `toolip reachability` | Report package usage observed in project source imports |
| `toolip install-scripts` | Inspect npm lifecycle scripts without executing them |
| `toolip sbom` | Generate CycloneDX 1.5 or SPDX 2.3 JSON |
| `toolip history` | Inspect local security history and score trends |
| `toolip config` | Initialize, validate, and inspect Toolip policy configuration |
| `toolip package-health <package> <version>` | Inspect package metadata/provenance through deps.dev |
| `toolip dependency-confusion` | Check internal-looking dependency names against public npm |
| `toolip git-history` | Scan Git history for deleted or historical secrets |
| `toolip doctor` | Run repository security hygiene checks |
| `toolip score` | Calculate a measurement-aware project security score |
| `toolip inspect <package>` | Inspect npm package metadata and risk signals |
| `toolip compare <packages...>` | Compare package maintenance and risk signals |
| `toolip licenses` | Analyze exact resolved direct-dependency licenses through deps.dev |
| `toolip alternatives <package>` | Suggest maintained alternatives |
| `toolip tree` | Display the resolved dependency graph |
| `toolip vault` | Manage encrypted local development secrets |
| `toolip git-audit` | Audit repository and ignore-file safety |
| `toolip pre-commit` | Run staged security checks before commit |
| `toolip hook install` | Install/manage the Toolip pre-commit hook |
| `toolip learn [topic]` | Read secure-development lessons |
| `toolip docker-scan` | Scan Dockerfiles for risky container patterns |
| `toolip monorepo` | Discover npm and pnpm workspace packages |
| `toolip audit-repo <url>` | Audit a public GitHub repository through `gh` |
| `toolip upgrade-pr <package> <version>` | Create a tested dependency-upgrade pull request |
| `toolip diff <base> [head]` | Summarize security-relevant Git changes |
| `toolip publish` | Generate a local static HTML security report |
| `toolip watch` | Rerun security checks as the project changes |
| `toolip announce` | Generate a deterministic security update summary |
| `toolip mcp` | Start the read-only Toolip MCP server over stdio |

Use command-specific help for current flags:

```bash
toolip scan --help
toolip doctor --help
toolip pre-commit --help
toolip vault --help
toolip mcp --help
```

## Security Analysis

### Vulnerability intelligence

Toolip queries **OSV.dev** using exact resolved package versions. Requests are deduplicated by package/version and executed with bounded concurrency. Analyzer/provider failures remain explicit instead of being silently interpreted as an all-clear.

### Dependency graph and package identity

Toolip builds one resolved dependency inventory from `package-lock.json`. Directness comes from root dependency declarations rather than physical npm hoisting, and each installed package instance retains its resolved path. npm workspace links are followed to the exact workspace package identity and version recorded by the lockfile.

The same graph now powers vulnerability analysis, dependency-tree output, SBOM relationships, install-script inspection, reachability correlation, and the dependency-health analysis used by `toolip scan`, `toolip doctor`, and `toolip score`. Health lookups and score penalties are deduplicated by exact `name@version`, while summary dependency counts still represent the full installed graph.

This means manifest declarations such as `^3.24.2`, `workspace:*`, `latest`, `npm:alias@version`, and Git specifiers are requirements only; they are never treated as installed versions when Toolip evaluates dependency health.

### Security scoring

Toolip security scoring is **measurement-aware**. A security dimension is not assigned `100/100` merely because a corresponding analyzer was not executed or a provider failed.

Dependency health uses the complete resolved transitive inventory for deprecation, maintenance, staleness, and freshness signals, alongside OSV vulnerability findings from the same dependency universe. The score model distinguishes dependency health, secrets, configuration, Git safety, execution status, and provider availability. Unavailable/failed dimensions remain explicit in structured output.

### AST security analysis

Toolip uses the TypeScript Compiler API for supported dangerous-code analysis. It resolves import/call targets rather than treating matching method names as equivalent, which avoids false positives such as confusing `RegExp.exec()` with `child_process.exec()`.

### Secret detection

Toolip detects every occurrence of supported secret patterns rather than only the first match per rule/file. Finding identities include stable occurrence information, and secret evidence is masked/fingerprinted rather than exposing token fragments.

Secret fingerprints are stable correlation and redaction identifiers, not password hashes, authentication primitives, secret commitments, or another security boundary. A fingerprint derived from a low-entropy value may be guessable and should be treated as sensitive report metadata.

Test files are not automatically treated as safe. Known synthetic fixtures can be marked explicitly; genuine credentials retain their security severity regardless of file location.

### Git-history scanning

Historical scanning processes Git output incrementally instead of materializing the entire patch history in memory. Deleted credentials remain detectable without publishing raw secret material.

### Container checks

`toolip docker-scan` checks Dockerfiles for root execution, secret-like `ARG`/`ENV`, unpinned base images, remote `ADD`, and package-install cleanup issues. Matching is performed in a single indexed pass so repeated lines retain correct locations.

## Repository-Scale Execution

Toolip v2.2.x removes several repeated full-tree traversals from the analysis path.

A shared project context now owns project discovery and file inventory. Source analyzers use bounded text reads with file-size and binary safeguards. Commands report how many files were discovered, actually scanned, skipped, or failed to read.

Analyzer orchestration provides:

- bounded concurrency
- hard deadlines even for non-cooperative analyzers
- cancellation propagation
- partial-failure isolation
- deterministic output order
- explicit analyzer execution status

The goal is simple: a larger repository should increase useful work, not multiply redundant discovery and unbounded memory/network usage.

## Git and Developer Workflow Safety

### Pre-commit

Pre-commit mode scans the **staged change set by default** instead of rescanning the entire repository and blocking a commit on unrelated historical findings. Full-repository mode remains explicit when required.

### Hook installation

`toolip hook install` preserves existing hooks instead of blindly replacing `.git/hooks/pre-commit`. Toolip manages its own marked hook block and avoids silently deleting Husky/custom logic.

### Upgrade PRs

`toolip upgrade-pr` performs mutations inside a temporary Git worktree. The caller's current branch and dirty files are left untouched, including when install/tests/push/PR creation fail.

Package-manager behavior is selected from the project instead of hard-coding npm. Current handling covers npm, pnpm, and Yarn-compatible upgrade flows. If multiple supported lockfiles coexist, Toolip emits an explicit warning before using its deterministic `pnpm > yarn > npm` precedence so stale migration lockfiles are not silently ignored.

### Watch mode

Watch mode debounces rapid changes, queues a follow-up scan when analysis is already running, reports callback failures without terminating the watcher, and uses platform-appropriate directory watching so Node 24 on Windows does not depend on the unstable recursive watcher path that previously crashed libuv.

## MCP Server

Toolip includes a read-only MCP server over stdio:

```bash
toolip mcp
```

Filesystem-backed MCP tools are constrained to approved workspace roots. Toolip resolves canonical real paths before authorization, preventing `..` traversal and symlink escapes outside the configured workspace.

The MCP interface does not provide arbitrary shell execution or unrestricted filesystem writes.

See [docs/MCP.md](docs/MCP.md).

## Toolip Vault

Toolip Vault stores local development secrets using **AES-256-GCM** with keys derived through `scrypt` and per-vault random salt/IV material.

v2.2.x includes:

- schema/version validation with fail-closed malformed-vault handling
- serialized mutations using a vault-local lock
- temporary same-directory writes followed by atomic rename
- POSIX permission repair to `0600` where supported
- safe POSIX shell export using single-quote encoding
- JSON export for non-shell consumers
- shell-key validation at export time rather than storage time

See [docs/VAULT.md](docs/VAULT.md).

## License Intelligence

License facts now come from **deps.dev** for the exact resolved direct-dependency version. Toolip keeps policy interpretation local, but no longer maintains a tiny hard-coded map of package-name-to-license facts.

Provider failure is reported explicitly rather than converted into guessed metadata.

## Configuration

Toolip supports `.toolipignore` for scan exclusions and `toolip.config.json` for project policy.

```bash
toolip config init
toolip config validate
toolip config show
```

Configuration supports rule enablement, severity overrides, path-specific policy, suppressions with reasons/expiry, provider settings, include/exclude paths, and history retention.

## Reports and Automation

Toolip can produce:

- terminal findings
- structured JSON
- local history/trends
- CycloneDX 1.5 SBOM
- SPDX 2.3 SBOM
- static HTML security reports
- Git security diffs
- deterministic security announcements

Reports use normalized findings with stable rule IDs, confidence, remediation, source location, analyzer metadata, and redacted evidence.

## Architecture

Toolip v2.2.x is centered on three practical primitives:

1. **Project context** — discover project/files/dependencies once and reuse them.
2. **Analyzer contract** — security capabilities return one canonical normalized `Finding` model.
3. **Execution engine** — enforce bounded concurrency, deadlines, cancellation, failure isolation, deterministic aggregation, and provider status.

CLI, pre-commit, watch, HTML reporting, CI-oriented output, and MCP are adapters over those shared primitives rather than independent security engines.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ENGINEERING.md](docs/ENGINEERING.md).

## CI and Release Trust

Toolip's normal verification path includes:

```bash
npm run verify
```

The gate performs:

- changelog validation
- compiler-backed static quality checks
- production dependency audit (`npm audit --omit=dev --audit-level=high`)
- the complete behavioral test suite
- security-critical V8 coverage thresholds
- a clean TypeScript build
- built-package verification

Security-critical coverage is currently required to remain at or above:

- **75% statements**
- **75% lines**
- **65% branches**
- **85% functions**

CI runs supported Node versions across Ubuntu, macOS, and Windows and separately verifies the npm tarball users will receive.

The release guard:

```bash
npm run release:check
```

packs Toolip, installs that exact tarball in isolation, and verifies the packaged CLI rather than trusting the source-tree build.

GitHub release creation and npm publication remain isolated from ordinary CI. npm publication uses the dedicated trusted-publishing/OIDC workflow with least-privilege permissions; verified release commits on `main` can publish automatically, and the manual path still requires explicit authorization. Publication is idempotent when an exact version is already present on npm.

See [RELEASING.md](RELEASING.md).

## Development

```bash
npm ci
npm run verify
```

Run from source:

```bash
npm run dev -- --help
```

Build:

```bash
npm run build
node dist/src/index.js --help
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Engineering standards](docs/ENGINEERING.md)
- [Vulnerability intelligence](docs/VULNERABILITY-INTELLIGENCE.md)
- [AST security](docs/AST-SECURITY.md)
- [Reachability](docs/REACHABILITY.md)
- [Install-script analysis](docs/INSTALL-SCRIPT-ANALYSIS.md)
- [SBOM generation](docs/SBOM.md)
- [Git history](docs/GIT-HISTORY.md)
- [Docker scanning](docs/DOCKER-SCANNING.md)
- [Monorepos](docs/MONOREPOS.md)
- [MCP](docs/MCP.md)
- [Vault](docs/VAULT.md)
- [Watch mode](docs/WATCH.md)
- [Upgrade PRs](docs/UPGRADE-PRS.md)
- [Releasing](RELEASING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Security Policy

Toolip analyzes source code, dependency metadata, Git history, and developer secrets. Findings redact sensitive evidence by default, remote actions are explicit, and workspace boundaries are enforced where a remote/tool interface can select filesystem roots.

Report suspected Toolip vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Contributing

Focused security fixes, performance improvements, analyzer improvements, provider integrations, tests, and documentation corrections are welcome. Changes that alter security behavior require regression coverage and must preserve the canonical finding contract and release gates.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Author

Built by **Ashibuogwu Williams (`wbizmo`)**.

GitHub: https://github.com/wbizmo

## License

MIT © Ashibuogwu Williams.
