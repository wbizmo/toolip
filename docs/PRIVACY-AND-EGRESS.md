# Privacy, local scanning, and network egress

Toolip is an MIT-licensed, local-first security tool. Local-first does **not** mean every command is network-free. Installing Toolip with npm/npx, obtaining standalone archives, refreshing advisory feeds, running explicitly enabled integrations, or pulling an OCI image may contact other services. The absence of requests from one Node.js provider is **not** proof that the operating system, proxy, or external tools emitted no traffic.

## Scan traffic and consent

| Operation | Network exposure | What is disclosed | Strict `--offline` behavior |
| --- | --- | --- | --- |
| `toolip scan` | OSV advisory service when exact public dependencies need lookup; conditional FIRST EPSS/CISA KEV enrichment | Public ecosystem/package name, exact installed version; CVE identifiers | No advisory/registry provider requests through the modeled scan services; missing/stale evidence remains incomplete |
| `scan --licenses` | deps.dev | Public package identity and version | Lookup disabled, unavailable license evidence is not treated as a clean result |
| `scan --package-health` | Public npm registry | Eligible package identity and version | Provider lookup disabled |
| `scan --allow-go-tool-execution` | Go toolchain, potentially module proxy and checksum database | Go module names and versions | Rejected when combined with `--offline` |
| `scan --npm-provenance-policy` | npm public registry/provider and artifact metadata | Public package/artifact identifiers | Rejected when combined with `--offline` |
| `scan --enrich-cve CVE-... --allow-public-cve-lookup` | GitHub public advisories and NVD 2.0 | Explicit CVE identifier only | Rejected when combined with `--offline` |
| `toolip advisories npm @public/name 1.2.3 --allow-public-package-lookup` | GitHub Global Advisories | Explicitly entered public npm package **name**; exact version is evaluated locally after retrieval | `--offline` returns an offline/unknown-state result; cannot be combined with consent |
| `toolip privacy explain` | None | None | Explanatory only; not a measured egress audit |
| `toolip report verify`, `distribution verify-asset` | None for the local verification operation | None | Local signature/digest checks only |

An exact dependency version is only claimed when a supported lock or verified source proves it. A bare manifest range does not establish installation. Private or scoped npm package identifiers are not indiscriminately sent to public providers: source/registry eligibility and explicit scope consent remain relevant. A public package name typed into the manual GHSA command is transmitted only after its explicit `--allow-public-package-lookup` consent.

The optional GHSA package lookup deliberately does not claim exhaustive coverage. A missing record or non-vulnerable semver range is *not* proof the installed package is free of vulnerabilities. The page limit, invalid/ambiguous ranges, provider errors, withdrawn advisories and non-npm package-manager constraints are tracked separately.

## Other egress surfaces

- **Installation and updates:** npm/npx and package registries may transfer package names, client/network metadata, and download artifacts *before* the Toolip process starts. The candidate POSIX/Windows installers download signed manifests and matching release archives from GitHub only when run without `--dry-run`, using an independently supplied trust key.
- **Homebrew/OCI:** bottle/formula and image acquisition contacts the respective configured registry or repository. OCI `--network none` is a container runtime restriction and is different from Toolip's own `--offline` request handling.
- **GitHub/GitLab/Azure/Bitbucket integrations:** remote CI platforms, protected workflows, status reporting, and uploads have provider-defined network behavior independent of a local scan. Generator commands produce review-only candidates.
- **Notifications:** `toolip notify send` requires `--enable-network`, explicit destination details and a private delivery ledger. It sends bounded status metadata, not raw findings or source snippets, unless a report link is separately approved.
- **AI and external vaults:** opt-in providers require their own explicit configuration, disclosure, and network review. They are **not** covered by ordinary `scan --offline` claims.
- **Plugins/Go tooling:** explicitly enabled runtimes and independently installed tooling have boundaries that require separate verification. There is no automatic proof of their complete process-level network isolation.

## Inspection and threat model

Use `toolip privacy explain --offline` to inspect declared scan surfaces. Use `toolip privacy explain --command advisories-npm --allow-public-package-lookup` to inspect GHSA's exact-npm-name disclosure *without making the request*.

The source of truth is the bounded provider implementation plus cross-platform negative tests, not this document alone. Egress safety needs OS/network capture, private-name adversarial fixtures, DNS/proxy handling, cancellation and controlled provider failures. CI/CodeRabbit release acceptance and those independent measurements are pending; do not claim NDPR/GDPR certification or absolute network non-disclosure on the strength of a CLI flag.
