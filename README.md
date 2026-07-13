# Toolip

Developer-first supply-chain security, dependency intelligence, security auditing, Git safety, and encrypted local secrets management from the terminal.

Toolip helps developers inspect what enters their applications, identify risky code and configuration, protect credentials, understand dependency health, and improve project security without requiring a hosted account or dashboard.

## Status

The latest stable release is **Toolip v2.1.1**.

Toolip v2.1.1 combines local vulnerability intelligence, AST-based security analysis, supply-chain auditing, Git security, container checks, SBOM generation, configurable policy, shareable reports, GitHub workflows, unified dependency-health scoring, and a read-only MCP server.

## Why Toolip Exists

Modern applications rely on large dependency graphs, external services, environment secrets, package lifecycle scripts, Git history, containers, and automated delivery pipelines. Security issues often enter through ordinary development decisions rather than obviously malicious code.

Toolip brings security checks closer to the developer. It is designed to explain findings, distinguish confidence levels, provide practical remediation, and operate locally by default.

Toolip does not aim to replace enterprise security platforms. It focuses on useful, understandable checks developers can run during normal development.

## Design Principles

* Local-first and privacy-conscious
* Free and useful without an account
* Deterministic analysis where possible
* Explicit confidence for heuristic findings
* Stable, machine-readable output
* Actionable remediation
* Bounded resource usage
* Opt-in remote integrations
* Verified npm release artifacts
* One shared analysis engine across every interface
* One canonical dependency-health calculation across commands

## Installation

Install the latest stable release globally:

```bash
npm install -g toolip
```

Install a specific version:

```bash
npm install -g toolip@2.1.1
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

Scan dependencies and project security:

```bash
toolip scan
toolip doctor
toolip score
```

Audit Git safety:

```bash
toolip git-audit
toolip git-history
toolip pre-commit
```

Inspect dependency choices:

```bash
toolip inspect express
toolip compare axios got
toolip licenses
toolip tree
toolip alternatives request
```

Generate software bills of materials:

```bash
toolip sbom --format cyclonedx
toolip sbom --format spdx
```

Use the local encrypted vault:

```bash
toolip vault init
toolip vault set DATABASE_URL
toolip vault list
toolip vault get DATABASE_URL
```

Learn security concepts from the terminal:

```bash
toolip learn cors
toolip learn jwt
toolip learn dependencies
```

## Current Commands

| Command                                     | Purpose                                                               |
| ------------------------------------------- | --------------------------------------------------------------------- |
| `toolip self-test`                          | Run internal diagnostics                                              |
| `toolip profile`                            | Detect project technologies and structure                             |
| `toolip scan`                               | Analyze dependency and project risk                                   |
| `toolip vulnerabilities`                    | Match resolved npm dependencies against OSV.dev                       |
| `toolip ast-scan`                           | Analyze JavaScript and TypeScript through the TypeScript Compiler API |
| `toolip reachability`                       | Show package usage observed in source imports                         |
| `toolip install-scripts`                    | Inspect npm lifecycle scripts for suspicious behavior indicators      |
| `toolip sbom`                               | Generate CycloneDX 1.5 or SPDX 2.3 JSON                               |
| `toolip history`                            | Inspect local security history and score trends                       |
| `toolip config`                             | Initialize and validate Toolip policy configuration                   |
| `toolip package-health <package> <version>` | Inspect package metadata and provenance through deps.dev              |
| `toolip dependency-confusion`               | Check internal-looking package names against public npm               |
| `toolip git-history`                        | Scan local Git history for deleted or historical secrets              |
| `toolip doctor`                             | Run security hygiene checks                                           |
| `toolip score`                              | Calculate a project security score                                    |
| `toolip inspect <package>`                  | Inspect npm package metadata and risk signals                         |
| `toolip compare <packages...>`              | Compare package health and maintenance signals                        |
| `toolip licenses`                           | Analyze dependency licenses                                           |
| `toolip alternatives <package>`             | Suggest maintained package alternatives                               |
| `toolip tree`                               | Display dependency relationships                                      |
| `toolip vault`                              | Manage encrypted local secrets                                        |
| `toolip git-audit`                          | Audit repository and ignore-file safety                               |
| `toolip pre-commit`                         | Run blocking security checks before commit                            |
| `toolip hook install`                       | Install the Toolip pre-commit hook                                    |
| `toolip learn [topic]`                      | Read secure-development lessons                                       |
| `toolip docker-scan`                        | Scan Dockerfiles for risky container patterns                         |
| `toolip monorepo`                           | Discover npm and pnpm workspace packages                              |
| `toolip audit-repo <url>`                   | Audit a public GitHub repository through `gh`                         |
| `toolip upgrade-pr <package> <version>`     | Create a tested dependency-upgrade pull request                       |
| `toolip diff <base> [head]`                 | Summarize security-relevant Git changes                               |
| `toolip publish`                            | Generate a static HTML security report                                |
| `toolip watch`                              | Continuously rerun security checks as files change                    |
| `toolip announce`                           | Generate a deterministic security update summary                      |
| `toolip mcp`                                | Start the read-only Toolip MCP server over stdio                      |

Use command-specific help for current options:

```bash
toolip doctor --help
toolip scan --help
toolip score --help
toolip vault --help
```

## Core Capabilities

### Vulnerability Intelligence

Toolip matches resolved npm dependencies against OSV.dev and reports known disclosed vulnerabilities using exact package versions.

It separates disclosed vulnerabilities from general package-maintenance signals so security risk and dependency freshness are not treated as the same thing.

See [docs/VULNERABILITY-INTELLIGENCE.md](docs/VULNERABILITY-INTELLIGENCE.md).

### Dependency Intelligence

Toolip reads project manifests and lockfiles, identifies outdated or deprecated dependencies, inspects package metadata, compares alternatives, reports license distribution, and visualizes dependency relationships.

Toolip also integrates with deps.dev for package metadata, dependency graph information, license data, provenance, attestations, and advisory intelligence.

### Risk-Aware Dependency Scoring

Toolip v2.1 introduced a risk-aware dependency-health model.

The scoring engine distinguishes between:

* disclosed vulnerabilities
* deprecated packages
* missing maintainer signals
* stale publishing activity
* major version gaps
* minor version gaps
* patch version gaps

Vulnerability penalties receive the greatest weight. Maintenance and freshness penalties are independently capped, preventing outdated packages alone from collapsing dependency health to zero.

Toolip v2.1.1 also ensures that `toolip scan` and `toolip score` consume the same canonical dependency-health result.

### AST Security Analysis

Toolip uses the TypeScript Compiler API for semantic dangerous-code checks. It resolves supported imports and call targets instead of treating every matching method name as the same operation.

This prevents regular-expression calls such as `RegExp.exec()` from being reported as shell execution while retaining detection of resolved `child_process.exec()`, `execSync()`, `eval()`, and dynamic `Function` construction.

See [docs/AST-SECURITY.md](docs/AST-SECURITY.md).

### Reachability Analysis

Toolip maps resolved npm packages to JavaScript and TypeScript imports. It reports observed, possibly reachable, and not-observed states without claiming that static absence proves safety.

See [docs/REACHABILITY.md](docs/REACHABILITY.md).

### Install-Script Analysis

Toolip inspects npm lifecycle scripts without executing them. It reports network access, shell execution, filesystem changes, obfuscation, and environment-access indicators with explicit confidence.

See [docs/INSTALL-SCRIPT-ANALYSIS.md](docs/INSTALL-SCRIPT-ANALYSIS.md).

### Software Bill of Materials

Toolip generates CycloneDX 1.5 and SPDX 2.3 JSON documents from resolved npm dependencies.

See [docs/SBOM.md](docs/SBOM.md).

### Security Auditing

Toolip checks source and configuration files for secret exposure, unsafe execution, weak security configuration, open CORS policies, JWT risks, missing security-header verification, and other security hygiene concerns.

### Git Safety

Toolip audits sensitive file patterns, ignore rules, committed artifacts, and pre-commit risks.

Git-history scanning can detect credentials that were committed and later deleted. Historical test fixtures are classified separately from genuine application credentials, and evidence remains redacted.

### Docker and Container Security

Toolip scans Dockerfiles for risky patterns including:

* root execution
* secret-like `ARG` or `ENV` declarations
* unpinned base images
* remote `ADD` instructions
* package-install cleanup issues

See [docs/DOCKER-SCANNING.md](docs/DOCKER-SCANNING.md).

### Monorepo Support

Toolip discovers npm and pnpm workspaces and identifies package boundaries for per-workspace analysis and reporting.

See [docs/MONOREPOS.md](docs/MONOREPOS.md).

### Local Secrets Management

Toolip Vault provides password-protected local encryption for development secrets. Vault data remains on the user's machine and does not require accounts, synchronization, or hosted storage.

### Security Education

Learning mode explains security concepts, common mistakes, practical risks, secure alternatives, and recommended development practices.

### Reports and Automation

Toolip can generate:

* terminal reports
* structured JSON output
* historical security records
* CycloneDX and SPDX SBOMs
* static HTML security reports
* Git security diffs
* deterministic release summaries

These outputs can support CI, review workflows, historical comparison, and integration with other tools.

## Architecture

Toolip separates interfaces, application services, analyzers, providers, contracts, reporting, and storage.

Commands handle input and presentation. Application services orchestrate work. Analyzers return normalized findings. Providers isolate Git, filesystem, package registry, vulnerability database, and GitHub access. Storage implementations manage cache, policy, history, and baselines.

CLI commands, watch mode, HTML reports, GitHub automation, and the MCP server reuse the same security engine and shared finding contracts.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the architectural model and [docs/ENGINEERING.md](docs/ENGINEERING.md) for development standards.

## Toolip v2.1 Capabilities

Toolip v2.1.1 includes:

* OSV-backed CVE and vulnerability matching
* AST-based JavaScript and TypeScript security analysis
* package reachability evidence
* npm lifecycle-script inspection
* CycloneDX and SPDX SBOM generation
* historical security trends
* project policy and severity configuration
* deps.dev package intelligence
* dependency-confusion detection
* full Git-history secret scanning
* Dockerfile and container configuration analysis
* monorepo-aware discovery
* remote public repository audits
* tested dependency-upgrade pull requests
* security diffs between commits and branches
* static HTML report generation
* real-time terminal watch mode
* deterministic release-summary generation
* a read-only MCP server
* risk-aware dependency-health scoring
* unified dependency-health results across `scan` and `score`

Remote repository audits and pull-request creation remain opt-in and use the user's own GitHub authorization.

## Configuration

Toolip supports `.toolipignore` for scan exclusions and `toolip.config.json` for project policy.

Create a configuration file:

```bash
toolip config init
```

Validate it:

```bash
toolip config validate
```

Display the resolved configuration:

```bash
toolip config show
```

The configuration schema supports:

* include and exclude paths
* rule enablement
* severity overrides
* path-specific rule policy
* suppressions with reasons
* optional suppression expiry dates
* history retention
* provider settings
* OSV and deps.dev timeouts

## Output and Automation

Toolip commands use non-zero exit codes for blocking failures where appropriate.

Machine-readable reports are intended for CI, review workflows, historical comparison, and integration with other tools.

Toolip reports can include:

* report schema version
* Toolip version
* project identity
* summary counts
* normalized findings
* analyzer metadata
* provider status
* generation timestamp
* scoring breakdowns
* confidence levels
* evidence fingerprints
* remediation guidance

## GitHub Integration

Remote repository audits and dependency-upgrade pull requests use the authenticated GitHub CLI.

Authenticate before using GitHub-connected commands:

```bash
gh auth login
```

Audit a public repository:

```bash
toolip audit-repo https://github.com/owner/repository
```

Create a tested dependency-upgrade pull request:

```bash
toolip upgrade-pr express 5.1.0 --dry-run
toolip upgrade-pr express 5.1.0
```

## MCP Server

Toolip includes a read-only MCP server over stdio.

Start it with:

```bash
toolip mcp
```

The MCP server exposes supported security analysis tools without exposing arbitrary shell execution or unrestricted write operations.

See [docs/MCP.md](docs/MCP.md).

## Development

Install dependencies:

```bash
npm ci
```

Run the complete verification suite:

```bash
npm run verify
```

Run the CLI from source:

```bash
npm run dev -- --help
```

Build and execute the compiled CLI:

```bash
npm run build
node dist/src/index.js --help
```

Verify the exact npm release candidate:

```bash
npm run release:check
```

The release check performs type checking, tests, a clean production build, package verification, npm packing, isolated tarball installation, and packaged CLI execution.

## Release Safety

Toolip v1.0.6 exposed an important release-engineering failure: the published npm package did not contain the compiled CLI.

Toolip now verifies releases from the packed artifact rather than assuming a successful local build means the package is valid.

A release is blocked unless the tarball contains:

```text
package/package.json
package/README.md
package/LICENSE
package/dist/src/index.js
```

The packed CLI must also successfully run:

```bash
toolip --version
toolip self-test
toolip --help
```

Release verification also checks version synchronization, the CLI executable shebang, changelog validity, required package contents, and isolated installation of the exact tarball that will be published.

See [RELEASING.md](RELEASING.md) for the complete release policy.

## Security

Toolip handles sensitive source files and credentials. Findings redact evidence by default, and remote operations must be explicitly authorized.

Please report suspected Toolip vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Contributing

Contributions should include tests, clear tradeoffs, and accurate security claims.

Analyzer changes require regression coverage and must use the shared finding contracts.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Changelog

Release history and unreleased changes are maintained in [CHANGELOG.md](CHANGELOG.md).

## Author

GitHub: https://github.com/wbizmo

## License

Toolip is available under the MIT License.
