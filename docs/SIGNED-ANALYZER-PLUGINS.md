# Signed WebAssembly analyzer plugins

Toolip accepts one signed analyzer plugin through `doctor` or `scan` when an
operator explicitly enables executable extensions. Plugins are WebAssembly
modules using Toolip Analyzer API v1. Unsigned plugins, JavaScript modules,
WASI modules, and modules with any import are rejected.

```sh
toolip doctor \
  --analyzer-plugin ./team-analyzer.json \
  --analyzer-plugin-trust-store "$HOME/toolip/plugin-trust.json" \
  --analyzer-plugin-key-id team-analyzer-2026 \
  --enable-executable-plugins
```

The manifest is strict JSON. Its Ed25519 signature covers the canonical
manifest fields, including the module SHA-256, capability list, expiration and
resource limits. The module must be a regular non-symlink file in the same
directory as the manifest. The recommended trust store is a strict version 1
JSON file outside the scanned project. It maps key IDs to Ed25519 public PEMs
and `active` or `revoked` status, with optional canonical UTC `validFrom` and
`expiresAt` timestamps. A revoked key is denied on the next plugin load; key
rotation adds a new key ID before removing the old one. Trust store reads reject
symlinks, duplicate keys, unknown fields, invalid key types, validity-window
errors and files over 1 MiB or 100 key entries. `--analyzer-plugin-public-key`
remains available as an explicit one-off migration path, but it has no central
revocation or rotation policy. A changed module, untrusted/revoked/expired key,
expired manifest, unknown field or unsupported API is rejected before
execution.

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
module in a terminable worker with a 32 MiB V8 old-generation limit. After
signature and digest verification, WASM compilation, import inspection and ABI
export inspection also run in a separate terminable worker with a 32 MiB
old-generation limit and a 10-second deadline. This keeps attacker-controlled
module compilation off the caller's event loop; it does not provide an OS
memory or CPU sandbox. Infinite loops, cancellation, traps, invalid output,
path escapes, and budget exhaustion produce failed or incomplete plugin
coverage, which makes the enclosing Doctor/scorecard result incomplete or
failed. Findings and clean results both include the plugin digest, signer key
ID and coverage state in reports.
After signature verification, module bytes are retained in module-private
state rather than exposed on the public plugin object. This prevents callers
from mutating a typed array and executing code that no longer matches the
reported signer and digest.

For `F` snapshot files and `B` input bytes, Toolip validates/serializes input
and validates output in O(F+B) time with O(B+M+O) additional space, where `M`
is the declared WASM memory cap (at most 16 MiB) and `O` is the 1 MiB response
cap. Plugin execution is bounded by its signed deadline; its own worst-case
instruction cost is not predictable, so timeout termination is part of the
contract. Module hashing, linear section validation and worker transfer setup
are bounded by the 8 MiB module cap; compilation and ABI enumeration are
isolated in the validation worker. The worker is a capability boundary for the
no-import WASM module; it is not an OS sandbox for arbitrary native code. Node
workers and WebAssembly are required. The cross-platform Node matrix still
needs to verify this path.

Plugin signer trust stores are external strict JSON capped at 1 MiB and 100
keys. Parsing and public-key validation are `O(S + K)` time and space for store
bytes `S` and entries `K`; key lookup is expected `O(1)`. The CLI reloads the
store for each plugin load, so revocation takes effect on the next invocation.

Declarative signed JSON rule packs remain the preferred extension format for
literal checks. They run in-process without executable code. Plugins should be
enabled only for reviewed publishers and controlled CI inputs; the flag does
not make third-party analyzer logic trustworthy or eliminate false positives.
