# Toolip Architecture

Toolip v2 is a local-first security analysis platform with multiple interfaces over one shared security engine.

Toolip v2.2.0 simplifies that model around three practical primitives: **ProjectContext**, **Analyzer**, and the **execution engine**.

## 1. ProjectContext

A project execution should discover expensive facts once and reuse them.

`ProjectContext` owns reusable project state such as:

- canonical project root
- project profile
- file inventory
- bounded file-read behavior
- scan accounting/budgets
- manifest and resolved dependency information where required

Commands and analyzers should not independently re-walk the repository when the same execution already has a valid context.

## 2. Analyzer contract

Each analyzer implements one security responsibility and returns normalized findings through the shared `Analyzer`/`Finding` contracts.

An analyzer must not:

- print terminal output
- terminate the process
- invent a second finding model
- silently convert provider failure into an all-clear
- execute untrusted project code merely to inspect it

Legacy report compatibility belongs at serialization boundaries. Internal security reasoning uses the canonical finding contract.

## 3. Execution engine

The application execution layer is responsible for cross-cutting execution guarantees:

- bounded concurrency
- hard deadlines
- cancellation
- deterministic result ordering
- partial-failure isolation
- explicit execution status
- provider error propagation

A non-cooperative analyzer cannot keep the entire runner waiting forever, and one analyzer failure cannot discard successful sibling results.

## Dependency inventory

Resolved package identity comes from the project manifest/lockfile rather than physical npm hoisting.

The inventory retains exact package versions and install paths and resolves dependency edges using Node-style nearest `node_modules` semantics. Tree output, SBOM relationships, install-script inspection, reachability correlation, and dependency analysis should reuse this graph.

## Interfaces

The CLI, pre-commit workflow, watch mode, static report publisher, GitHub operations, and MCP server are adapters over shared application/security primitives.

Interfaces parse input, enforce interface-specific authorization, invoke application services, and render/serialize results. They do not own independent security engines.

## Providers

Providers isolate external systems such as npm, OSV, deps.dev, GitHub, Git, and the filesystem.

Provider code owns network/authentication mechanics. Security policy/severity remains in Toolip analysis/application logic.

Network paths must use bounded concurrency and explicit timeout/failure behavior. Provider unavailability must remain visible to callers.

## Trust boundaries

### Filesystem

Source reads are bounded by file/byte budgets. Oversized or unsuitable files are skipped explicitly and reflected in scan accounting.

### MCP

MCP filesystem roots are canonicalized with `realpath()` and authorized by containment inside approved canonical workspace roots. Traversal and symlink escapes fail closed.

### Secrets

Secret evidence is redacted/fingerprinted by default. Raw credentials are not a normal report contract.

### Remote operations

GitHub repository audits and pull-request creation are opt-in. npm publishing is isolated from ordinary CI and release authorization is explicit.

## Storage

Local storage includes configuration, history, vault data, and any future durable cache/baseline implementations.

A storage abstraction should exist only when it provides a real lifetime/consistency guarantee. Toolip should not introduce an in-memory cache abstraction that claims a multi-hour lifetime across one-shot CLI process exit.

Vault persistence is a special security-sensitive store: updates are serialized, written to a temporary same-directory file, and atomically renamed over the primary encrypted vault.

## Engineering rules

- Discover repository state once per execution when possible.
- Commands do not implement security analysis.
- Analyzers do not print output or exit the process.
- Providers do not decide finding severity.
- One canonical `Finding` model is used internally.
- Findings use stable rule and occurrence identifiers.
- Evidence is redacted by default.
- Network/analysis failures remain explicit.
- Concurrency and memory usage must be bounded.
- Security claims require behavioral regression tests.
- Supported Node majors must run on Linux, macOS, and Windows CI.
- Every release is verified from the exact packed npm artifact.
- `package.json` is the only package-version source of truth.
