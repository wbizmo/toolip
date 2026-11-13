# Software Bill of Materials

Toolip generates local JSON software bills of materials from supported lockfile
graphs. Supported inputs include npm, pnpm, Yarn, Python, Go, Cargo, Maven,
Gradle exports, and Composer where the corresponding exact inventory is
available. Missing or ambiguous resolution stays incomplete; manifest ranges
are not presented as installed versions.

The npm-compatible resolver recognizes npm `package-lock.json` formats 2 and
3, pnpm lockfile formats 6 through 9, Yarn Classic v1, and Yarn Berry metadata
formats 4, 5, 6 and 8 (Yarn 2–4). Unsupported versions and ambiguous lockfiles
remain incomplete. Exact lock identities preserve workspace location, install
name, alias key, peer context, dependency edges, registry origin and declared
integrity where the format supplies them. Berry workspace bookkeeping entries
with synthetic `0.0.0-use.local` versions are resolved from captured workspace
manifests and are not exposed as registry packages. Lockfile integrity is
provenance metadata only: a digest recorded in a lockfile is always
`declared-not-verified` until an independent artifact check succeeds. A
manifest range alone never creates a resolved installed identity.

## CycloneDX

```bash
toolip sbom --format cyclonedx --output bom.cdx.json
```

The generated document uses CycloneDX 1.5.

## SPDX

```bash
toolip sbom --format spdx --output bom.spdx.json
```

The generated document uses SPDX 2.3.

Toolip includes package names, exact resolved versions, canonical package URLs,
instance-specific references, direct/development metadata, and root dependency
relationships. Package URLs are parsed through `packageurl-js`. The graph
namespace binds complete package identities (including available registry and
integrity metadata), edges, unresolved declarations and warnings.

CycloneDX components and SPDX package metadata distinguish artifact integrity
from publisher trust and code safety. Lock hashes are reported as declared but
unverified by default; an opt-in npm policy also downloads and hashes the exact
public-registry tarball against the lock integrity. Go tool mode may report the
module checksum as verified after the official checksum-database check.
Missing or malformed evidence is `unknown`. Publisher trust remains `unknown`
unless a separate provenance verification establishes it, and code safety is
`not asserted`. SBOM output is local and may include a custom registry origin
or declared digest; review it before sharing. No project source code is
uploaded.

## Opt-in npm provenance verification

`scan` and `sbom` can verify npm SLSA provenance against an operator-owned
policy. The policy must be a regular JSON file outside the scanned repository;
repository content cannot supply its own trust rules. Each package rule binds
the expected Fulcio issuer, exact certificate identity URI and canonical GitHub
source repository. A key such as `example@1.2.3` pins one exact package version;
an `example` key applies the same publisher identity to all versions of that
name:

```json
{
  "version": 1,
  "packages": {
    "example": {
      "certificateIssuer": "https://token.actions.githubusercontent.com",
      "certificateIdentity": "https://github.com/acme/example/.github/workflows/release.yml@refs/tags/v1.2.3",
      "sourceRepository": "https://github.com/acme/example"
    }
  }
}
```

Use it explicitly:

```sh
toolip scan --npm-provenance-policy "$HOME/toolip/npm-provenance.json"
toolip sbom --npm-provenance-policy "$HOME/toolip/npm-provenance.json" \
  --allow-public-scope
```

Only exact public npm registry origins are queried. Scoped package names are
withheld unless `--allow-public-scope` is present. The verifier checks registry
package/version identity, downloads the exact lock-resolved tarball with
redirects disabled, hashes its bytes against the lock SHA-512, then checks the
signed PURL/SHA-512 subject, provenance source repository, and bundle signature
under the configured issuer and certificate identity. Packument and attestation
responses are capped at 8 MiB each; streamed tarballs are capped at 32 MiB and
are not buffered as a complete archive. Each request times out after five seconds by
default, and Sigstore verification runs in a worker with a 64 MiB V8
old-generation limit and a 20-second hard stop. A non-verified result remains
visible as unknown, withheld, unavailable, untrusted or invalid and makes an
opted-in scan partial.

`artifactIntegrity: verified` means downloaded public npm bytes matched the
lock digest. `declared-not-verified` means those bytes were unavailable or
outside the supported origin/size policy; `mismatch` is an explicit untrusted
failure. Publisher trust and code safety are separate results. The scanner does
not execute the archive. Stage A applies the same issuer/source policy from a
protected repository variable to the exact archive digests its trusted scanner
already measured. Missing policy or any unverified package blocks Stage A.
Non-npm publisher provenance remains open parts of issue #77.

For Stage A, configure the GitHub repository variable
`TOOLIP_STAGE_A_NPM_PROVENANCE_POLICY` with the version 1 JSON policy. Every
locked npm package needs either an exact `name@version` rule or a package-name
rule. This variable is read only by the protected-base workflow; repository
content cannot supply or relax the policy. The workflow deliberately remains
incomplete until the variable is configured for a dependency-bearing PR.
