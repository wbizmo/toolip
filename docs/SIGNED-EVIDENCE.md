# Signed scan evidence

Toolip can attach an Ed25519 signature to a JSON scan report. The signature
covers canonical report data, including findings, severity counts, analysis
coverage and reasons. It also binds a caller-supplied stable project ID and the
captured Git revision and index digest, the dependency-lock graph digest, the
Toolip configuration digest, and a stable SHA-256 digest of every path and
content hash in the immutable project snapshot. It also binds each selected
rule pack's ID, canonical payload digest, trust mode and signing key ID. The
resolved dependency graph digest when lockfile resolution succeeds. The report
payload includes the scan findings and coverage state, so changing coverage or
any captured source, dependency-graph or rule-pack identity invalidates the
signature.
When `--npm-provenance-policy` is configured, the report also contains the
per-package verification status and verified issuer, certificate identity and
source repository; those records are part of the signed report payload.
The signed envelope
also binds a SHA-256 digest of the Toolip package manifest and every file in
the runtime module tree (`dist/src` for an installed package, or `src` for a
source checkout). This identifies the scanner code and package metadata; it
does not include the external Node.js runtime or installed dependency bytes.
Canonical JSON sorts
object keys; arrays retain their report order. `generatedAt` and the absolute
checkout path are omitted so equivalent evidence can be verified across
machines.

The source snapshot digest represents the bounded inventory captured for that
scan, including binary file hashes. It does not claim that files excluded by
discovery rules, unreadable inputs or budget limits were scanned; those
conditions must remain visible in the signed report's coverage and reasons.
The signature does not establish organizational trust by itself. Verification
can apply an operator-managed trust store with project binding, validity,
rotation, revocation and maximum-age policy. The explicit one-off public-key
options remain a migration path and do not provide managed revocation policy.

Create an owner-only private key and sign a scan locally:

```sh
toolip scan --output scan-report.json \
  --evidence-signing-key ./evidence-ed25519-private.pem \
  --evidence-signing-key-id org-security-2026 \
  --evidence-project-id acme/payments
```

The private key file must be a regular non-symlink file with owner-only POSIX
permissions. The JSON report contains the public verification material needed
to identify the algorithm, key ID, project ID, source digests, signed payload
digest and signature. It never contains the private key.

Verify against a public key and the expected project identity:

```sh
toolip report verify scan-report.json \
  --public-key ./evidence-ed25519-public.pem \
  --key-id org-security-2026 \
  --project-id acme/payments
```

To require a previously reviewed scanner artifact, pass its expected digest:

```sh
toolip report verify scan-report.json \
  --public-key ./evidence-ed25519-public.pem \
  --key-id org-security-2026 \
  --project-id acme/payments \
  --scanner-artifact-sha256 <reviewed-runtime-digest>
```

To reject a valid but stale report for a different captured source tree, also
require the expected digest:

```sh
toolip report verify scan-report.json \
  --public-key ./evidence-ed25519-public.pem \
  --key-id org-security-2026 \
  --project-id acme/payments \
  --source-tree-sha256 <expected-source-tree-digest>
```

Verification requires the exact expected key and project IDs. Signatures older
than 90 days are rejected by default; `--max-age-days` may be set from 0 to 365
for a local verification policy. Unsigned, expired, mismatched and altered
reports return a non-zero status and an explicit result. An unsigned report
remains a normal scan report, but it has no cryptographic integrity claim.
Verification without `--source-tree-sha256` proves the signed captured subject
and signature age, but does not establish that the report describes the
verifier's current checkout.

SBOM output can also produce a detached DSSE envelope containing an in-toto
statement. It signs the canonical CycloneDX/SPDX document digest and binds the
project and key identities, Toolip version, issue time, and available Git,
lock-graph, configuration and captured source-tree digests. It also binds the Toolip runtime module
tree digest, which can be required during verification with
`--scanner-artifact-sha256`. For example:

```sh
toolip sbom --output sbom.json \
  --signing-key ./evidence-ed25519-private.pem \
  --signing-key-id org-security-2026 \
  --project-id acme/payments

toolip sbom verify sbom.json \
  --attestation sbom.json.attestation.json \
  --public-key ./evidence-ed25519-public.pem \
  --key-id org-security-2026 \
  --project-id acme/payments
```

Signing requires a file output so the sidecar names the exact document. The
attestation signs the canonical JSON form, so formatting-only changes do not
change its subject digest. The SBOM remains a standard CycloneDX or SPDX JSON
document. This configured-key signature is not an OIDC identity proof or
Sigstore certificate; key ownership and rotation remain part of the caller's
trust policy.

This local-key format does not prove who controlled the key, that the key was
not compromised, that the scanner binary was independently attested, or that
the scanned project is benign. It is not a Sigstore/OIDC provenance statement.
Use a separately managed trust store and review key ownership and rotation
outside the report. The project ID is supplied by the caller and must match the
identity expected by the verifier.

### Operator-managed Ed25519 trust store

Report and SBOM verification can use an external versioned trust store instead
of a one-off public-key file. Keep this policy under operator control, outside
the verified project. Both verification commands reject a trust-store path
inside `--project-root` (which defaults to the current directory). Set
`--project-root` to the source project being verified when running elsewhere.
Example:

```json
{
  "version": 1,
  "projectId": "acme/payments",
  "maxAgeDays": 90,
  "keys": {
    "release-2026-v2": {
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "status": "active",
      "validFrom": "2026-01-01T00:00:00.000Z",
      "expiresAt": "2027-01-01T00:00:00.000Z"
    },
    "release-2025-v1": {
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "status": "revoked",
      "revokedAt": "2026-10-01T00:00:00.000Z"
    }
  }
}
```

The store accepts only bounded unique-key JSON, Ed25519 public keys, a
configured project ID, a maximum evidence age, and explicit active or revoked
key records. Revocation immediately rejects evidence for that key. To rotate,
add the reviewed replacement as active and revoke the compromised or retired
key; evidence signed by the revoked key must be re-signed to be accepted under
the new policy. Validity windows and signature age are checked during
verification. The existing `--public-key --key-id --project-id` options remain
available as an explicit one-off migration path; they do not consult or imply a
managed revocation policy. Replace the abbreviated PEM placeholder above with
the actual trusted Ed25519 public key before using the file.

```sh
toolip report verify scan-report.json \
  --trust-store ./operator-trust.json \
  --key-id release-2026-v2 \
  --project-root /path/to/verified/project

toolip sbom verify sbom.json \
  --attestation sbom.json.attestation.json \
  --trust-store ./operator-trust.json \
  --key-id release-2026-v2 \
  --project-root /path/to/verified/project
```

## Exact npm release tarball attestations

`toolip npm-attestation create` signs the SHA-512 digest and npm PURL of the
exact `.tgz` bytes, together with the expected GitHub source repository and
full commit, Toolip version, and digest of the Toolip runtime modules. It reads
`package/package.json` from a bounded tar stream and never extracts or executes
archive contents. The signing operation uses the current runner's OIDC
identity; outside a trusted OIDC-enabled job it cannot create a Sigstore
signature.

`toolip npm-attestation verify` requires the exact tarball, bundle, certificate
issuer, certificate identity URI, source repository, source commit, and scanner
runtime digest. Missing expected identity values are not treated as success.
Changed tarball bytes, package identity, source, scanner digest, certificate
identity, or signature return a nonzero result. Bundle and tarball files must
be bounded regular non-symlink files.

The protected `publish.yml` workflow creates the release tarball once, signs
and verifies that file against the GitHub Actions issuer and the exact
`publish.yml` workflow identity on `main`, preserves the verified bundle as a
workflow artifact, and passes that same tarball path to `npm publish`. npm
trusted publishing also emits npm's registry provenance. This binds the
attestation to the bytes published by that job; it does not establish a
reproducible build, prove that source code is safe, include external runtime or
dependency bytes in the scanner digest, or replace independent review of the
release environment and protected branch configuration. The remote OIDC flow
and published package have not been exercised by local verification.

Complexity is `O(T + U + A)` time for compressed tarball bytes `T`, uncompressed
tar bytes `U`, and bounded Sigstore bundle bytes `A`; the CLI caps these at 32
MiB, 128 MiB, and 16 MiB respectively. Main-process live archive data is
bounded by `T + U`, with one 1 MiB package manifest and the bundle; certificate
verification runs in a worker capped at 64 MiB V8 old-generation memory and 20
seconds. V8 limits are not total process RSS limits.

For local syntax and structural inspection, without an OIDC signer:

```sh
toolip npm-attestation create --help
toolip npm-attestation verify --help
```
