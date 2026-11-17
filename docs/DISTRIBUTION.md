# Toolip distribution workflow

**State:** code-only, operator-reviewed distribution candidates. These source files do **not** establish a signed, independently verified, or publicly released v3.2.1 binary, OCI image or Homebrew formula. The npm CLI remains authoritative until actual parity evidence and owner release approval.

## Source identity and build boundaries

The same exact `package.json` release version and full Git commit SHA must match every candidate. Each builder requires a clean checkout. A separately governed Stage A bootstrap and the release gate (#55) must approve the candidate *before* untrusted install/build scripts or publication. A clean Git checkout by itself is not that approval.

| Candidate | Source code | Trust inputs | Output |
| --- | --- | --- | --- |
| Runtime-embedded Bun | `scripts/build-standalone-candidate.mjs` | Exact Bun version, **out-of-band Bun SHA-256**, package version, Git SHA, supported target | Unsigned raw candidate in an existing directory outside checkout |
| Archive packaging | `scripts/package-standalone-candidate.mjs` | Explicit supported Bun target and raw candidate directory | Root-only `.tar.gz` or `.zip`; deterministic archive layout, unsigned |
| Local detached signature | `scripts/create-distribution-manifest.mjs` | Exact release Git SHA; operator-managed, out-of-band Ed25519 private key; checked candidate archives | `release-manifest.json`, detached base64 `release-manifest.sig` |
| Signature verification | `toolip distribution verify-asset` | Separately obtained Ed25519 public key, exact version/SHA, local signed manifest and archive | Local verification result only; never grants release approval |
| Homebrew formula | `toolip distribution homebrew-candidate` | Verified signed archive manifest with exact supported Darwin/Linux digests | Unpublished review-only formula for `wbizmo/homebrew-tap` |
| OCI image | `scripts/build-oci-distribution.mjs` | Clean release checkout, exact source SHA/version, digest-pinned builder/runtime base images | Unsigned, unpushed multi-platform OCI tar in an existing directory outside checkout |

The standalone builder requires `TOOLIP_BUN_BINARY`, `TOOLIP_BUN_VERSION`, `TOOLIP_BUN_SHA256`, `TOOLIP_RELEASE_GIT_SHA`, `TOOLIP_RELEASE_VERSION`, `TOOLIP_STANDALONE_TARGET`, and `TOOLIP_STANDALONE_CANDIDATE_DIR`. The candidate directory must exist outside the source checkout. The packaging step uses `TOOLIP_STANDALONE_CANDIDATE_DIR`, `TOOLIP_DISTRIBUTION_ASSETS_DIR`, `TOOLIP_RELEASE_VERSION` and `TOOLIP_STANDALONE_TARGET`.

The manifest signer additionally requires `TOOLIP_DISTRIBUTION_OUTPUT_DIR` and `TOOLIP_DISTRIBUTION_SIGNING_KEY`. Never commit or transmit the signing private key to a PR workflow or scan runner. The builder deliberately refuses an already existing target output instead of silently overwriting a reviewed archive.

The OCI candidate requires `TOOLIP_BUILDER_IMAGE`, `TOOLIP_RUNTIME_IMAGE`, `TOOLIP_OCI_OUTPUT` (a simple `.tar` filename), and `TOOLIP_OCI_OUTPUT_DIR` (a pre-existing, outside-checkout absolute directory), in addition to the release identity. The Dockerfile uses numeric non-root UID 65532 and does not run project install scripts at image startup. Docker/npm registry access during building is **not** equivalent to an offline runtime scan.

## Installers

The POSIX and Windows scripts under `distribution/install/` must be inspected locally. They require an exact version, source Git SHA and public trust anchor obtained **independently** from the download host. They download only manifests and matching archives and refuse mismatched signatures/checksums. No installation uses `sudo`, changes a system PATH, runs an arbitrary project build, or automatically updates itself.

- POSIX installs to an approved per-user HOME subdirectory, rejects directory symlinks and refuses to replace an existing executable.
- PowerShell installs only beneath LOCALAPPDATA and currently supports verified Windows x64 candidates, not unverified Windows ARM64.
- Both provide `--dry-run` or `-DryRun` planning without obtaining remote artifacts. Remove the user-local Toolip executable manually to uninstall; neither script adds shell-profile entries.

Shell-level directory checks are not equivalent to a proven race-free `openat2` sandbox. The installer trust boundary and representative filesystem attacks require independent release verification.

## Mandatory acceptance before publishing

1. Trusted, protected bootstrap and full #95/#96 code and provenance acceptance, including approved source revision, builder digest and third-party base-image attestations.
2. Node/OS runtime parity across source analyzers, dependency ecosystems, policy states, SARIF, VEX/SBOM, trusted WASM/rule packs, offline behavior, and exit codes on clean machines without a preinstalled Node/Bun runtime.
3. Deterministic per-platform archive contents, source SHA/ABI mapping, third-party license inventory, runtime/toolchain provenance, tamper and cross-architecture rejection.
4. Signature and manifest verification against an independently owned public-key trust root; approved SBOM, audit and provenance for npm, archives and OCI.
5. Actual startup/CPU/RSS/throughput measurements and candidate/cross-platform CI. A static generator and unexecuted regression tests cannot establish performance claims.
6. Explicit maintainer authorization under #55 before tagging, pushing OCI images, publishing Homebrew formula, uploading GitHub Release assets, or claiming v3.2.1 released.

Licensing: **Toolip MIT**, **Copyright (c) 2026 Zivora Logic Ventures**, maintained by **Zivora Labs**. Retain all third-party licenses for bundled runtimes, dependencies and base images. No private or unlicensed advisory database is redistributed by this workflow.
