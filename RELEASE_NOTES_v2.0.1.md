# Toolip v2.0.1

Toolip v2.0.1 improves the accuracy and consistency of Git-history secret scanning.

## Fixed

- Password-like values committed inside test files are now classified as low-severity potential test fixtures.
- Git-history findings now retain the historical source file path.
- Test fixtures use medium confidence and fixture-specific remediation guidance.
- Genuine credentials outside test files retain their original high or critical severity.
- Redacted evidence and secret fingerprints remain unchanged.

## Verification

- TypeScript typecheck passed.
- Complete test suite passed.
- Clean production build passed.
- Package-content verification passed.
- CLI version, self-test, help output, and Git-history command checks passed.

Built by Ashibuogwu Williams (`wbizmo`).
