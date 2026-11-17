# Advisory sources and evidence confidence

Toolip's advisory pipeline is source-aware. It must not treat a version string in a product/CPE record as an installed npm, PyPI, Go, Cargo, Maven, or Composer package instance. A lockfile-resolved package graph and the applicable ecosystem-specific version semantics are prerequisites for exact installed-package findings.

## Current source contracts

| Source | Purpose | Important limitations |
| --- | --- | --- |
| [OSV](https://google.github.io/osv.dev/api/) | Baseline package-ecosystem vulnerability lookup using package name and exact version; may use a trusted offline snapshot | Unknown/private origins, unresolved versions, stale or unsigned data cannot be treated as clean |
| [FIRST EPSS](https://www.first.org/epss/) | Exploitation probability enrichment of identified public CVEs | Probability is not proof of exploitability for a particular installation |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerability context | Catalog absence is not proof a vulnerability is unexploited |
| [GitHub Global Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories) | Explicit public CVE and exact-npm-name lookups; preserves advisory IDs, CVE aliases, type, severity, affected range and withdrawal | An API response page is not exhaustive; reviewed/unreviewed/malware types are distinct; one GHSA cannot be used as universal package identity evidence |
| [NVD 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Explicit public CVE metadata and NVD CVSS/CWE context | CPE product ranges are not an authoritative package-manager mapping |

Toolip preserves conflicting source assertions and does not automatically collapse two source records into a single installed-package finding merely because an alias matches. OSV findings use the lock-resolved ecosystem/package/version identity; optional GHSA/NVD evidence is kept separately until matching is justified.

## Public npm GHSA lookup

`toolip advisories npm @public/example 1.2.3 --allow-public-package-lookup`

Use `--type reviewed` (default), `--type unreviewed`, or `--type malware` to request one explicit GHSA advisory category. Results retain their type and are not silently combined across categories.

- The package name is sent in an explicit `ecosystem=npm&affects=...` GitHub API query. Toolip evaluates the supplied exact semver **locally** against the version ranges reported for that same package identity.
- Unsupported ranges, prerelease nonmatches, malformed provider data, duplicate advisory identities and a full first page are reported as **partial** or **unknown**, not as verified clean.
- A record may report `affected: yes`, `no`, or `unknown`. `no` means only that the record's parseable GHSA range did not match; it does not certify the package safe.
- `--offline` or absent consent causes no GHSA request and returns an offline result. With an explicitly denied network request, a failure remains a failure.
- NVD never determines npm version impact through an inferred CPE match. CVE enrichment is a separate, opt-in command/scan option.

## Snapshot and redistribution restrictions

Signed local snapshot authenticity, source timestamp, freshness, and complete input coverage are separate checks. A signed snapshot can still contain old or inaccurate source records. Preserve upstream provider terms, attribution and allowed redistribution rights before bundling any advisory data in an npm package, OCI image, or standalone binary.

The Node/OS test matrix, rate-limit behavior, provider compatibility, large-dataset accuracy and cross-ecosystem matching acceptance require independent verification. This document does not represent the later batches as released.
