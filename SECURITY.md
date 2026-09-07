# Security Policy

## Supported versions

Security fixes are provided for the latest stable Toolip release. Older releases may be deprecated when they contain known packaging, security-boundary, or dependency defects.

| Version | Supported |
| --- | --- |
| 2.2.x | Yes |
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
