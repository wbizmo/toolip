# Signed scan evidence

Toolip can attach an Ed25519 signature to a JSON scan report. The signature
covers canonical report data, including findings, severity counts, analysis
coverage and reasons. It also binds a caller-supplied stable project ID and the
captured Git revision, index digest, dependency-lock graph digest and Toolip
configuration digest when those values are available. The signed envelope
also binds a SHA-256 digest of the Toolip package manifest and every file in
the runtime module tree (`dist/src` for an installed package, or `src` for a
source checkout). This identifies the scanner code and package metadata; it
does not include the external Node.js runtime or installed dependency bytes.
Canonical JSON sorts
object keys; arrays retain their report order. `generatedAt` and the absolute
checkout path are omitted so equivalent evidence can be verified across
machines.

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

Verification requires the exact expected key and project IDs. Signatures older
than 90 days are rejected by default; `--max-age-days` may be set from 0 to 365
for a local verification policy. Unsigned, expired, mismatched and altered
reports return a non-zero status and an explicit result. An unsigned report
remains a normal scan report, but it has no cryptographic integrity claim.

SBOM output can also produce a detached DSSE envelope containing an in-toto
statement. It signs the canonical CycloneDX/SPDX document digest and binds the
project and key identities, Toolip version, issue time, and available Git,
lock-graph, and configuration digests. It also binds the Toolip runtime module
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
