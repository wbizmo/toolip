# Standalone executables — feasibility and release restrictions

Toolip's authoritative implementation is the TypeScript/Node CLI. The candidate Bun `--compile` path embeds a JavaScript runtime in an executable; it does **not** rewrite Toolip into a native Rust or Go engine, prove improved performance, or guarantee that every dynamic dependency and plugin works outside npm.

## Proposed runtime matrix (not certified)

| Target ID | Intended output | State |
| --- | --- | --- |
| `bun-linux-x64` | `linux-x64-gnu.tar.gz` | Candidate builder only; ABI and runtime parity unverified |
| `bun-linux-arm64` | `linux-arm64-gnu.tar.gz` | Candidate builder only; runtime parity unverified |
| `bun-linux-x64-musl` | `linux-x64-musl.tar.gz` | Experimental target; do not claim Alpine support without runtime tests |
| `bun-linux-arm64-musl` | `linux-arm64-musl.tar.gz` | Experimental target; do not claim Alpine support without runtime tests |
| `bun-darwin-x64` | `darwin-x64.tar.gz` | Candidate; macOS signature/notarization status unverified |
| `bun-darwin-arm64` | `darwin-arm64.tar.gz` | Candidate; macOS signature/notarization status unverified |
| `bun-windows-x64` | `windows-x64.zip` | Candidate; Windows Authenticode and runtime status unverified |
| Windows ARM64 | None | Not built or supported by the present candidate toolchain |

Real release filenames prepend `toolip-<exact-package-version>-`. Source code may contain a target name without proving the corresponding file exists.

## Packaging and verification

- The raw candidate builder checks an independently specified Bun executable SHA-256 and version, copies it to a private build directory, and requires a clean source checkout at the exact supplied Git revision.
- Archive packaging streams one regular executable under a root-level `toolip` or `toolip.exe` entry. Tar entries use canonical USTAR checksums; Windows archives contain one stored ZIP entry.
- The local signer binds every archive filename, target, size and SHA-256 to the exact source revision with Ed25519. Signing a candidate alone **does not** confer release approval.
- `toolip distribution verify-asset` checks detached signature, expected version, source SHA and actual archive bytes using a separately supplied public key. Trust anchors must never be learned solely from the same release URL as the manifest.
- `toolip distribution homebrew-candidate` only renders a formula if the signed manifest contains exact supported macOS/Linux archives. It never writes to or publishes `wbizmo/homebrew-tap`.

## Required cross-platform release tests

Perform actual help/version, scan, full-policy, offline, report/SARIF, SBOM/VEX and supported ecosystem smoke tests on Linux/macOS/Windows with no separately installed Node/Bun/npm, then compare canonical findings and exit codes to the verified npm CLI. Confirm dynamic imports, WASM rules, external Git, Go opt-in, CA certificates, filesystem encoding, symlink resistance, signature verification, and the plugin capability model.

Record each platform's archive size, binary start latency, cold/warm full-scan wall time, peak heap/RSS, CPU and errors. Mark unsupported cells rather than guessing. Perform network/proxy/DNS negative tests and supply-chain signing and license review before publication. GitHub Actions matrices, CodeRabbit and owner signoff are separate required evidence.

## Upgrade and removal

No auto-update or shell-profile editing is implemented. Verify a newly obtained, separately signed artifact before replacing an existing user-local installation. The candidate installers intentionally refuse to overwrite an existing binary; an operator must manually remove or back up an older version after checking the newer archive. Verify `toolip --version` and re-run security checks after any actual approved upgrade.

License: MIT — Copyright (c) 2026 Zivora Logic Ventures, maintained by Zivora Labs; bundled runtime/toolchain/OS libraries retain their respective third-party terms.
