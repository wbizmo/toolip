# Declarative rule packs

Toolip `doctor` and `scan` can load one bounded JSON rule pack. The current
format is deliberately declarative: rules match a literal string in selected
file extensions. A pack cannot provide JavaScript, a module entrypoint, a
regular expression, a callback, or a custom file reader. Toolip never imports
or executes pack content, so these rules receive no filesystem, vault, or
network capability.

Signed packs are required by default. Verification uses an Ed25519 signature
over canonical JSON: recursively sorted object keys, unchanged array order, and
the top-level `signature` property omitted. The trusted key ID must match the
signature envelope, and the pack must be within its signed validity period.
The CLI reads both packs and public keys as bounded regular files without
following symlinks. Private signing keys should remain in the publisher's
separate signing environment.

An unsigned pack is rejected unless the operator explicitly opts in for one
local run:

```sh
toolip doctor --rule-pack ./team-rules.json \
  --rule-pack-public-key ./team-rules.pub.pem \
  --rule-pack-key-id team-rules-2026
```

For a reviewed local pack without a signature, the operator may use
`--allow-unsigned-rule-pack`. That option is an explicit trust override and
must not be copied into unattended CI. JSON fields are strict and unknown keys
are rejected.

Example unsigned payload before the publisher adds its `signature` envelope:

```json
{
  "schema": "toolip.dev/rule-pack/v1",
  "id": "example",
  "apiVersion": 1,
  "issuedAt": "2026-11-01T00:00:00.000Z",
  "expiresAt": "2026-12-01T00:00:00.000Z",
  "rules": [
    {
      "id": "TLP-EXAMPLE-001",
      "title": "Example marker",
      "severity": "high",
      "confidence": "medium",
      "literal": "INTERNAL_ONLY_MARKER",
      "fileExtensions": [".ts", ".tsx"],
      "remediation": "Remove the marker from source control."
    }
  ]
}
```

Rule IDs must use `TLP-<PACK-ID>-NNN`; a literal is limited to 256 characters,
the pack to 256 rules and 1 MiB, and validity to 180 days. A scan accepts at
most 16 already-verified packs and 512 combined rules. Matching is at most once
per rule per file. Findings omit the matched literal and source excerpt. If
the 10,000-finding output limit is reached, Toolip marks the analysis partial
instead of presenting truncated results as complete.

For `F` eligible files, `B` scanned bytes, and `R` configured rules, literal
matching is O(BR) worst-case time with O(R) additional rule-index space beyond
the scan's existing file/content storage. `R` is capped at 512; each source
file is already subject to the security-doctor read budget. Report cache keys
include pack digest and trust identity, so changing a pack or signer invalidates
cached findings.

For signed executable analyzer extensions, see
[Signed WebAssembly analyzer plugins](SIGNED-ANALYZER-PLUGINS.md). Those
plugins are separately signed, disabled by default, run with no host imports,
and receive only bounded immutable snapshot bytes. They do not execute as
JavaScript or gain OS filesystem/network APIs. Their Node 22/24 and
Windows/macOS/Linux worker behavior still requires the remote CI matrix.
