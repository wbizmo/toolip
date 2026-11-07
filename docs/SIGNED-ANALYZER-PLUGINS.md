# Signed WebAssembly analyzer plugins

Toolip accepts one signed analyzer plugin through `doctor` or `scan` when an
operator explicitly enables executable extensions. Plugins are WebAssembly
modules using Toolip Analyzer API v1. Unsigned plugins, JavaScript modules,
WASI modules, and modules with any import are rejected.

```sh
toolip doctor \
  --analyzer-plugin ./team-analyzer.json \
  --analyzer-plugin-public-key ./team-analyzer.pub.pem \
  --analyzer-plugin-key-id team-analyzer-2026 \
  --enable-executable-plugins
```

The manifest is strict JSON. Its Ed25519 signature covers the canonical
manifest fields, including the module SHA-256, capability list, expiration and
resource limits. The module must be a regular non-symlink file in the same
directory as the manifest. The caller supplies the trusted public key and key
ID independently. A changed module, untrusted key, expired manifest, unknown
field or unsupported API is rejected before execution.

The only capability in API v1 is `read-snapshot`. Toolip sends the bounded,
immutable text snapshot as JSON. Plugins have no host imports, WASI, filesystem,
network, report-writing, vault or process APIs. A plugin cannot request more
capabilities than this API implements. Its output contains rule IDs, concise
messages, remediation, and source locations; Toolip validates paths against
the exact input snapshot, applies shared redaction, and does not accept source
excerpts or arbitrary metadata.

The WASM ABI exports one bounded `memory`, `toolip_alloc(i32) -> i32`,
`toolip_analyze(i32, i32) -> i32`, and `toolip_output_len() -> i32`. The
analyzer receives a UTF-8 JSON object with `schemaVersion: 1` and a `files`
array. It returns UTF-8 JSON with `schemaVersion: 1` and a `findings` array.
Each finding uses the strict fields `ruleId`, `severity`, `confidence`,
`file`, `line`, and `column`. Rule IDs must match
`TLP-PLUGIN-<PLUGIN-ID>-NNN`. Toolip supplies generic title, message and
remediation text instead of forwarding plugin-authored prose, so a plugin
cannot echo source credentials into reports.

The signed limits cap each plugin at 10 seconds, 256 64-KiB WASM pages, 8 MiB
of input, and 1 MiB of output; smaller limits are recommended. Toolip runs the
module in a terminable worker with a 32 MiB V8 old-generation limit. Infinite
loops, cancellation, traps, invalid output, path escapes, and budget exhaustion
produce failed or incomplete plugin coverage, which makes the enclosing
Doctor/scorecard result incomplete or failed. Findings and clean results both
include the plugin digest, signer key ID and coverage state in reports.
After signature verification, module bytes are retained in module-private
state rather than exposed on the public plugin object. This prevents callers
from mutating a typed array and executing code that no longer matches the
reported signer and digest.

For `F` snapshot files and `B` input bytes, Toolip validates/serializes input
and validates output in O(F+B) time with O(B+M+O) additional space, where `M`
is the declared WASM memory cap (at most 16 MiB) and `O` is the 1 MiB response
cap. Plugin execution is bounded by its signed deadline; its own worst-case
instruction cost is not predictable, so timeout termination is part of the
contract. The worker is a capability boundary for the no-import WASM module;
it is not an OS sandbox for arbitrary native code. Node workers and WebAssembly
are required. The cross-platform Node matrix still needs to verify this path.

Declarative signed JSON rule packs remain the preferred extension format for
literal checks. They run in-process without executable code. Plugins should be
enabled only for reviewed publishers and controlled CI inputs; the flag does
not make third-party analyzer logic trustworthy or eliminate false positives.
