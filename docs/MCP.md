# Toolip MCP Server

Toolip exposes a read-only MCP server over stdio.

```bash
toolip mcp
```

The server provides supported Toolip security operations such as security doctor analysis, SBOM generation, and security diffs without exposing arbitrary shell execution or unrestricted filesystem writes.

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
