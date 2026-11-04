# Security Policy

## Supported versions

Security fixes are provided for the latest stable Toolip release. Older releases may be deprecated when they contain known packaging, security-boundary, or dependency defects.

| Version         | Supported                         |
| --------------- | --------------------------------- |
| 2.2.x           | Yes                               |
| 2.1.x and older | Best-effort / upgrade recommended |

## Reporting a vulnerability

Do not disclose vulnerabilities publicly before maintainers have had a reasonable opportunity to investigate.

Report suspected vulnerabilities through GitHub's private vulnerability reporting feature for the Toolip repository.

Include, where possible:

- affected Toolip version
- operating system and Node.js version
- reproduction steps
- expected and observed behavior
- security impact
- affected command/interface
- suggested remediation, if known

Do not include live credentials or unnecessary sensitive project data in a report.

## Security principles

Toolip is designed around the following boundaries:

- **local-first analysis** — project source is not uploaded by default
- **redacted findings** — secret evidence is masked/fingerprinted rather than reproduced raw
- **explicit provider state** — provider failure is not silently converted into a clean security result
- **canonical filesystem authorization** — MCP paths are resolved and contained inside approved workspace roots
- **bounded execution** — file reads, concurrency, analyzer deadlines, and scan work are bounded
- **non-destructive Git automation** — mutable upgrade workflows are isolated from the caller's worktree
- **atomic encrypted storage** — vault mutations are serialized and atomically replaced
- **release isolation** — ordinary CI does not receive npm publish credentials
- **packed-artifact verification** — releases are tested from the npm tarball users install

## Sensitive findings

Toolip reports should not be treated as a secret store. Raw secret values are not part of the normal finding contract.

If a Toolip bug causes credential material to be exposed in terminal/JSON/HTML output, treat that as a security vulnerability and report it privately.

## Remote operations

Commands that interact with GitHub or other remote services are opt-in and use the user's configured authorization. MCP does not expose arbitrary shell execution or unrestricted writes.

## Release security

Toolip's release verification includes a production dependency audit, security-critical execution coverage, cross-platform CI, clean build verification, npm tarball inspection, isolated installation, and packaged CLI smoke tests.

The preferred npm publishing path uses GitHub Actions trusted publishing/OIDC with least-privilege permissions and a separately protected release environment.

## Batched PR security and release isolation

For v3.2.1, each PR is validated with typechecks, build/tests, runtime dependency advisory audit, Gitleaks secrets scanning and CodeQL analysis. Security fixes require hostile-input and regression tests and must report partial/failed/unknown scan states honestly. See [the implementation plan](docs/V3.2.1-IMPLEMENTATION.md).

PR workflows never receive npm publish credentials. `publish.yml` and `github-release.yml` are manual-only, not automatically triggered by merges to `main`. Repository administrators must separately configure required PR checks, code scanning rules and protected `npm-release` environment reviewers; adding workflow YAML alone does not enforce these settings.

`publish.yml` is configured for npm trusted publishing (OIDC, provenance, no stored token), but this remains a release target until the npm-side trusted publisher is registered and a real publish is verified. New analyzer security capabilities and signed reports are likewise release targets, not shipped guarantees until their issues are completed and verified.

## Secret scanning

Gitleaks scans pull requests and, run locally, full history. `.gitleaks.toml` extends the default rules and allowlists only synthetic sequential-digit tokens (`ghp_1234567890…`, `npm_1234567890…`) in three reviewed secret-detection test fixtures; both the file and the pattern must match. Any other finding fails the scan. Do not widen the allowlist to directories, and never commit real credentials, even revoked ones.

## Dependency vulnerability policy

CI audits production **and** development dependencies at every severity (`npm run audit:runtime`, `npm run audit:all`), verifies registry signatures (`npm audit signatures`) and checks the lockfile (`npm run verify:lockfile`: registry-only HTTPS sources, strong integrity hashes, reviewed install scripts). Advisories are fixed by upgrading, or by a documented `overrides` entry in `package.json` when a transitive package has a patched release that its parent has not yet adopted; findings are never suppressed or downgraded. Remove an override once the parent depends on the patched range.
