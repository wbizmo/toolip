# Toolip MCP Server

Toolip exposes a read-only MCP server over stdio.

```bash
toolip mcp
```

The server provides Toolip security doctor analysis, policy checks, SBOM
generation, and security diffs without exposing arbitrary shell execution or
unrestricted filesystem writes. A closed per-tool authorization table requires
the declared `read-code`, `read-git`, and `scan` capabilities. These local read
capabilities are enabled by default; `external-network`, `write-reports`,
`create-pr`, and `vault-access` are disabled by default. Unknown capability
names and non-boolean settings are rejected at server startup.

An organization policy is optional and is configured only at server startup,
outside the scanned workspaces:

```bash
toolip mcp \
  --allow-root /workspace/project \
  --organization-policy /etc/toolip/org-policy.json \
  --organization-policy-public-key /etc/toolip/org-policy.pub \
  --organization-policy-key-id org-policy-v3 \
  --organization-policy-issuer security.example/toolip \
  --require-organization-policy
```

The server checks the signature, key ID, issuer, and expiration before applying
the organization policy. Tool arguments and repository files cannot select or
change these trust values. The policy envelope and public key must resolve
outside every approved workspace. Stdio is a local process transport; these
settings do not authenticate a remote MCP client or establish an HTTP trust
boundary. Any future remote transport needs separate authentication and
authorization.

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

## Budgets and policy

Each tool call has a configured timeout, process-wide call and concurrency
limits, bounded file and byte budgets, and a maximum serialized response size.
Cancellation propagates through discovery, analysis and large SBOM
serialization; component and edge output yields periodically so a request
timeout can interrupt serialization after the snapshot has been captured. A
timed-out uncooperative operation retains its active slot until it settles, so
repeated requests cannot create unbounded background work. Hard ceilings cap concurrency at 32 tools,
the server lifetime at 100,000 accepted/rejected calls, and each operation at
15 minutes. TypeScript AST work has a separate process-wide limit of one active
worker and one queued request; queued cancellation is immediate, and further
requests fail closed as incomplete rather than retaining an unbounded number of
project snapshots. Responses carry the protocol request ID in `_meta` when the SDK
provides a valid ID; error bodies also include it. `toolip_policy_check` parses the versioned
policy captured in the same immutable project snapshot as the scan. Repository
policy remains untrusted, so its suppressions cannot grant a passing result.
When a response exceeds its byte, node, or structure budget, MCP returns an
explicit `incomplete` decision with `outputTruncated: true`; truncated analysis
output is never represented as complete.
Policy checks default to `offline: true`. A caller must explicitly request
`offline: false`, and the local server must enable the `external-network`
capability, before advisory lookups can leave the workspace. Other read-only
tools do not use that capability.
