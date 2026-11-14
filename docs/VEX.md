# VEX import and signing

Toolip imports OpenVEX 0.2 and CycloneDX 1.5/1.6 assessments for an exact
package URL, including Toolip's install-path qualifier. An assessment for a
different installed instance or advisory does not match a finding. Missing
static imports do not establish that vulnerable code is unreachable.

## Applying assessments

Unsigned documents can be validated and displayed, but `not_affected` never
suppresses a vulnerability unless the document's Ed25519 signature verifies
against a public key supplied out of band and its authority is explicitly
allowed. The assessment must include a recognized justification, evidence,
assessment timestamp, and an expiry no more than one year after assessment.
The signer name in the VEX document is not proof of identity.
When a valid `not_affected` assessment matches both the advisory ID (or alias)
and the exact installed-instance PURL, `toolip vulnerabilities` removes that
finding from the active list. JSON output retains the complete suppressed
finding under `vex.suppressed` with its assessment evidence; text output reports
the suppressed count. Mismatched, unsigned, untrusted or expired assessments
leave the finding active.

Suppression is recorded only for a finding matched and validated in the current
application. A `vexAssessment` field already present on a finding cannot
suppress it.

```sh
toolip vulnerabilities \
  --vex-file organization.vex.json \
  --vex-format openvex \
  --trust-vex-authority 'Product Security' \
  --vex-trusted-public-key ./trust/product-security-ed25519.pub.pem \
  --vex-trusted-key-id product-security-2026
```

The key ID flag is optional when the public key is pinned directly, but using
it also checks the signed document's key identifier. Invalid signatures fail
the import. Unsigned or unverified `not_affected` entries remain findings and
are reported as rejected assessments. Other statuses do not remove findings.

## Signing and verification

Exported documents are unsigned until an authorized owner signs them. Keep the
private key outside the repository with owner-only permissions.

```sh
toolip vex sign \
  --input assessment.vex.json \
  --output assessment.signed.vex.json \
  --format openvex \
  --signing-key ./keys/product-security-ed25519.pem \
  --key-id product-security-2026

toolip vex validate \
  --input assessment.signed.vex.json \
  --format openvex \
  --trusted-public-key ./trust/product-security-ed25519.pub.pem \
  --trusted-key-id product-security-2026
```

OpenVEX signatures use the `x-toolip-signature` extension. CycloneDX signatures
use a `toolip:signature` metadata property. Both are Ed25519 signatures over
the canonical complete JSON document with the signature field removed and the
key ID bound into the signed message. Reordering object keys preserves the
signature; changing an assessment or other document field invalidates it.
Signing and verification accept bounded canonical JSON and never execute
document content.

OpenVEX and CycloneDX timestamps are checked as exact UTC calendar values;
impossible dates, duplicate CycloneDX component references, and component
version/PURL disagreements are rejected. Parsing indexes `C` CycloneDX
components and visits `A` assessment/product references in O(B + C + A) time
and O(C + A) additional space, where `B` is the bounded input document size.
Applying assessments builds an O(A) lookup and visits `F` findings and their
advisory aliases `L`, for O(A + F·L) time and O(A + F) additional space.
Canonical signing/verification is O(B) time and space and is capped at 32 MiB;
the CLI applies a stricter 16 MiB input-file cap.

Signature verification authenticates the exact document under the configured
key. It does not prove that a human assessment is correct, that code is safe,
or that static analysis established non-reachability. Review, key rotation,
revocation and external trust-store governance remain organization
responsibilities.
