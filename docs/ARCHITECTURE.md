# Toolip Architecture

Toolip v2 is structured as a local-first security analysis platform with multiple interfaces over one shared analysis engine.

## Architectural Layers

### Interfaces

The CLI, future MCP server, watch mode, report publisher, and automation commands are interfaces. They parse input, invoke application services, and render results. They do not contain security analysis logic.

### Application Services

Application services orchestrate analyzers, providers, caching, configuration, history, policy, and reporting. They manage concurrency, cancellation, timeouts, and partial failures.

### Analyzers

Analyzers implement one security responsibility and return normalized findings through the shared `Analyzer` interface. An analyzer must not print terminal output or directly control process exit codes.

### Providers

Providers isolate external systems such as npm, OSV, deps.dev, GitHub, Git, and the filesystem. Network behavior, caching, retry policy, and authentication remain outside analyzers.

### Contracts

Findings, reports, analyzer results, rule definitions, severities, confidence levels, and source locations are stable contracts shared by all interfaces.

### Storage

Storage implementations persist cache entries, history, baselines, and configuration. Application services depend on storage interfaces rather than concrete file formats.

## Engineering Rules

- Commands do not implement security analysis.
- Analyzers do not print output.
- Providers do not decide severity.
- Findings use stable rule identifiers.
- Evidence is redacted by default.
- Network failures may produce partial results but must be explicit.
- Every analyzer requires unit, regression, and integration coverage.
- Every release is verified from the packed npm artifact.
- `package.json` is the only version source of truth.
