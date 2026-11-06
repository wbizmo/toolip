# Secret scanning implementation

This document describes the v3.2.1 implementation work. The published npm package remains v2.2.1 until the final release is explicitly approved; package users should consult documentation shipped with their installed version.

## Files and budgets

The scanner reads bounded, readable text files rather than trusting an extension allowlist. It explicitly includes credential files such as `.npmrc`, `.pypirc`, `.netrc`, dotenv files, and nested credential/configuration files. Readable-file discovery excludes declaration files (`*.d.ts`), source maps (`*.map`), and the default ignored paths `node_modules`, `dist`, `coverage`, `build`, `.git`, and `.toolip-vault.json`, as well as paths ignored by `.toolipignore`. These policy exclusions are not counted as incomplete coverage, so a complete scan can leave readable files unexamined. Known binary formats are excluded before reads, and content-confirmed binary assets with unrecognized extensions are excluded from eligible secret-scan coverage. Known text/source extensions and credential-named files remain eligible even when a binary read prevents inspection. Other files are handled by the bounded text reader, which classifies binary, oversized, failed, and cancelled reads and contributes eligible incomplete reads to scan coverage. Default `TextFileReader` per-file and total-byte budgets remain in force, so hitting a budget is reported as incomplete coverage rather than a clean scan.

## Detectors

Current secret patterns include GitHub token shapes, AWS access-key IDs, npm tokens and registry auth values, private-key headers, credential-bearing HTTP URLs, password assignments, JWT secrets, and common API-key assignments. These are indicators, not exhaustive credential validation. A clean result means no unsuppressed match was reported among files successfully read and examined; check the suppressed count and policy IDs when interpreting results. It does not prove that no credential exists.

## Suppression policy

Comments or markers in scanned files never suppress findings. A trusted caller may supply fixture suppressions scoped to an exact rule ID and repository-relative file path. Every entry requires a stable ID, owner, and justification; an expired or invalid expiry is rejected. Results expose the suppressed count and policy IDs. The working-tree and staged-blob scanner use the same policy interface, and the Git-history scanner applies the same validated policy shape to added lines.

## Output handling

AST evidence records the finding type and source location without copying source expressions. Install-script findings omit command text. Reports and MCP output redact supported token shapes, credential assignments, URL userinfo, and query parameters. Fingerprints are pseudonymized with a process-local HMAC key before output, preserving within-process correlation without exposing guessable raw hashes; pseudonyms do not correlate across separate process runs. This pattern-based filtering cannot identify every arbitrary secret expression. Analyzer errors are redacted before returning or printing. This defense does not replace safe handling of reports or careful secret rotation after exposure.
