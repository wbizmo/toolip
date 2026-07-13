# Toolip v2.1.1

Toolip v2.1.1 unifies dependency-health scoring across the CLI.

Toolip v2.1.0 introduced the new risk-aware scoring model, but `toolip score` and `toolip scan` still calculated dependency health through separate paths. That could cause both commands to report slightly different values for the same project.

This release removes that inconsistency.

## Fixed

- `toolip scan` and `toolip score` now consume the same canonical dependency-health result.
- Dependency health is calculated once inside the dependency-scanning service.
- The old finding-based calculation is no longer used by the `scan` command.
- Both commands now report an identical dependency-health score for the same project state.
- Added regression tests preventing future scoring-path divergence.

## Verification

- Changelog validation passed.
- TypeScript typecheck passed.
- Complete test suite passed.
- Clean production build passed.
- npm package-content verification passed.
- Tarball inspection passed.
- Isolated package installation passed.
- CLI version, self-test, help, scan, and score checks passed.

Built by Ashibuogwu Williams (`wbizmo`).
