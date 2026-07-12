# Toolip

Developer-first supply-chain security, dependency intelligence, security auditing, Git safety, and encrypted local secrets management from the terminal.

Toolip helps developers inspect what enters their applications, identify risky code and configuration, protect credentials, understand dependency health, and improve project security without requiring a hosted account or dashboard.

## Status

The latest stable release is Toolip v1.0.7.

Toolip v2.0.0 is under active development on the `v2-development` branch. The v2 work focuses on real vulnerability intelligence, AST-based analysis, stronger release engineering, historical tracking, Git security, hardened local secrets management, container analysis, SBOM generation, monorepo support, GitHub integrations, terminal workflows, and an MCP server.

## Why Toolip Exists

Modern applications rely on large dependency graphs, external services, environment secrets, package lifecycle scripts, Git history, containers, and automated delivery pipelines. Security issues often enter through ordinary development decisions rather than obviously malicious code.

Toolip brings security checks closer to the developer. It is designed to explain findings, distinguish confidence levels, provide practical remediation, and operate locally by default.

Toolip does not aim to replace enterprise security platforms. It focuses on useful, understandable checks developers can run during normal development.

## Design Principles

- Local-first and privacy-conscious
- Free and useful without an account
- Deterministic analysis where possible
- Explicit confidence for heuristic findings
- Stable, machine-readable output
- Actionable remediation
- Bounded resource usage
- Opt-in remote integrations
- Verified npm release artifacts
- One shared analysis engine across every interface

## Installation

Install the latest stable release globally:

```bash
npm install -g toolip
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

| Command | Purpose |
| --- | --- |
| `toolip self-test` | Run internal diagnostics |
| `toolip profile` | Detect project technologies and structure |
| `toolip scan` | Analyze dependency and project risk |
| `toolip vulnerabilities` | Match resolved npm dependencies against OSV.dev |
| `toolip ast-scan` | Analyze JavaScript and TypeScript through the TypeScript Compiler API |
| `toolip reachability` | Show package usage observed in source imports |
| `toolip install-scripts` | Inspect npm lifecycle scripts for suspicious behavior indicators |
| `toolip sbom` | Generate CycloneDX 1.5 or SPDX 2.3 JSON |
| `toolip history` | Inspect local security history and score trends |
| `toolip doctor` | Run security hygiene checks |
| `toolip score` | Calculate a project security score |
| `toolip inspect <package>` | Inspect npm package metadata and risk signals |
| `toolip compare <packages...>` | Compare package health and maintenance signals |
| `toolip licenses` | Analyze dependency licenses |
| `toolip alternatives <package>` | Suggest maintained package alternatives |
| `toolip tree` | Display dependency relationships |
| `toolip vault` | Manage encrypted local secrets |
| `toolip git-audit` | Audit repository and ignore-file safety |
| `toolip pre-commit` | Run blocking security checks before commit |
| `toolip hook install` | Install the Toolip pre-commit hook |
| `toolip learn [topic]` | Read secure-development lessons |

Use command-specific help for current options:

```bash
toolip doctor --help
toolip scan --help
toolip vault --help
```

## Core Capabilities

### Dependency Intelligence

Toolip reads project manifests and lockfiles, identifies outdated or deprecated dependencies, inspects package metadata, compares alternatives, reports license distribution, and visualizes dependency relationships.

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

Toolip audits sensitive file patterns, ignore rules, committed artifacts, and pre-commit risks. Git hooks can run Toolip checks before changes enter repository history.

### Local Secrets Management

Toolip Vault provides password-protected local encryption for development secrets. Vault data remains on the user's machine and does not require accounts, synchronization, or hosted storage.

### Security Education

Learning mode explains security concepts, common mistakes, practical risks, secure alternatives, and recommended development practices.

### Reports

Commands can produce terminal output and machine-readable reports for automation. Toolip v2 introduces a versioned report schema shared across scanning, history, diffs, publishing, watch mode, and MCP tools.

## Architecture

Toolip v2 separates interfaces, application services, analyzers, providers, contracts, reporting, and storage.

Commands handle input and presentation. Application services orchestrate work. Analyzers return normalized findings. Providers isolate Git, filesystem, package registry, vulnerability database, and GitHub access. Storage implementations manage cache, policy, history, and baselines.

This structure allows CLI commands, future watch mode, HTML reports, GitHub automation, and the MCP server to reuse one security engine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the architectural model and [docs/ENGINEERING.md](docs/ENGINEERING.md) for development standards.

## Toolip v2 Scope

Toolip v2.0.0 is planned to add:

- OSV-backed CVE and vulnerability matching
- AST-based JavaScript and TypeScript security analysis
- dependency reachability evidence
- package lifecycle-script inspection
- CycloneDX and SPDX SBOM generation
- historical security trends
- project policy and severity configuration
- deps.dev package health intelligence
- dependency confusion detection
- full Git-history secret scanning
- Dockerfile and container configuration analysis
- monorepo-aware scanning
- remote public repository audits
- safe dependency-upgrade pull requests
- security diffs between commits and branches
- static HTML report publishing
- real-time terminal watch mode
- local release-summary generation
- an MCP server for approved Toolip operations
- hardened Toolip Vault key derivation and storage controls

Remote repository audits, pull-request creation, and report publishing remain opt-in. They use the user's own GitHub authorization and are not required for local Toolip features.

## Configuration

Toolip currently supports `.toolipignore` for scan exclusions.

Toolip v2 will introduce a versioned `toolip.config.json` schema supporting path policies, rule severity overrides, test-fixture treatment, suppressions with reasons and expiry dates, provider settings, cache controls, and monorepo behavior.

## Output and Automation

Toolip commands use non-zero exit codes for blocking failures where appropriate. Machine-readable reports are intended for CI, review workflows, historical comparison, and integration with other tools.

Toolip v2 reports include:

- report schema version
- Toolip version
- project identity
- summary counts
- normalized findings
- analyzer metadata
- provider status
- generation timestamp

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

Toolip v1.0.6 exposed an important release-engineering failure: the published npm package did not contain the compiled CLI. Toolip now verifies releases from the packed artifact rather than assuming a successful local build means the package is valid.

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

See [RELEASING.md](RELEASING.md) for the complete release policy.

## Security

Toolip handles sensitive source files and credentials. Findings redact evidence by default, and remote operations must be explicitly authorized.

Please report suspected Toolip vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Contributing

Contributions should include tests, clear tradeoffs, and accurate security claims. Analyzer changes require regression coverage and must use the shared finding contracts.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Changelog

Release history and unreleased changes are maintained in [CHANGELOG.md](CHANGELOG.md).

## Author

Toolip is built and maintained by Ashibuogwu Williams (`wbizmo`).

GitHub: https://github.com/wbizmo

## License

Toolip is available under the MIT License.

## Vulnerability Intelligence

Toolip matches resolved npm dependencies against OSV.dev. See [docs/VULNERABILITY-INTELLIGENCE.md](docs/VULNERABILITY-INTELLIGENCE.md).
