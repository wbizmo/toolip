# Secret scanning implementation

This document describes the v3.2.1 implementation work. The published npm package remains v2.2.1 until the final release is explicitly approved; package users should consult documentation shipped with their installed version.

## Files and budgets

The scanner reads bounded, readable text files rather than trusting an extension allowlist. It explicitly includes credential files such as `.npmrc`, `.pypirc`, `.netrc`, dotenv files, and nested credential/configuration files. Known binary formats are excluded before reads; other files are handled by the bounded text reader, which classifies binary, oversized, failed, and cancelled reads and contributes them to scan coverage. Default `TextFileReader` per-file and total-byte budgets remain in force, so hitting a budget is reported as incomplete coverage rather than a clean scan.

## Detectors

Current secret patterns include GitHub token shapes, AWS access-key IDs, npm tokens and registry auth values, private-key headers, credential-bearing HTTP URLs, password assignments, JWT secrets, and common API-key assignments. These are indicators, not exhaustive credential validation. A clean result means no supported pattern matched in the files that were successfully read; it does not prove that no credential exists.

## Suppression policy

Comments or markers in scanned files never suppress findings. A trusted caller may supply fixture suppressions scoped to an exact rule ID and repository-relative file path. Every entry requires a stable ID, owner, and justification; an expired or invalid expiry is rejected. Results expose the suppressed count and policy IDs. The working-tree and staged-blob scanner use the same policy interface, and the Git-history scanner applies the same validated policy shape to added lines.

## Output handling

AST evidence records the finding type and source location without copying source expressions. Install-script findings omit command text. Reports and MCP output recursively redact common token, credential assignment, URL userinfo, query-parameter, and fingerprint fields. Analyzer errors are redacted before returning or printing. This defense does not replace safe handling of reports or careful secret rotation after exposure.
