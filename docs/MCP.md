# Toolip MCP Server

Toolip exposes a read-only MCP server over stdio.

```bash
toolip mcp
```

The server provides supported Toolip security operations such as security doctor analysis, SBOM generation, and security diffs without exposing arbitrary shell execution or unrestricted filesystem writes.

Toolip starts only the stdio transport; the SDK's HTTP/session/OAuth features are not used. `package.json` declares the SDK at `^1.32.2`; the lockfile advisory gate rejects any installed version below `1.32.0` (the advisory boundary); see [Runtime and Dependency Security](RUNTIME-AND-DEPENDENCY-SECURITY.md).

## Git revisions

`toolip_diff` validates `base` and `head`, resolves them to commit IDs and never passes caller text to Git as an option. Ranges and revision expressions are rejected; failures return an `isError` result containing `{"error":{"code","message"}}` with `GIT_REVISION_INVALID` or `GIT_REVISION_NOT_FOUND` and no filesystem paths. See [Git Security Behavior](GIT-SECURITY.md).

## Workspace boundary

Filesystem-backed MCP requests are constrained to approved workspace roots.

Toolip does not authorize paths with string-prefix checks. Requested roots are canonicalized with filesystem `realpath()` resolution before authorization, and containment is evaluated against canonical approved roots.

This blocks common boundary escapes including:

- `..` traversal outside the workspace
- sibling paths sharing the same textual prefix
- symlinks inside the workspace that resolve to files/directories outside it
- alternate path spellings that resolve to an unauthorized location

If a requested path cannot be resolved or resolves outside every approved root, the MCP operation fails closed.

## Security model

The MCP boundary is intentionally narrower than direct local CLI use:

- read-only Toolip operations only
- no arbitrary command execution
- no unrestricted write API
- no implicit authorization of arbitrary absolute paths
- project analysis remains subject to Toolip scan budgets and bounded file reads
- findings retain normal redaction rules

The workspace boundary is a filesystem authorization boundary; it is not a sandbox for arbitrary third-party code execution. Toolip analyzers themselves must continue to avoid executing untrusted project code.
