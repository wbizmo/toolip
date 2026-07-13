# Toolip v2.1.0

Toolip v2.1.0 introduces a risk-aware dependency-health scoring model.

The previous score treated every outdated dependency as a medium-severity finding worth a 12-point penalty. A project with 11 outdated packages could therefore accumulate 132 points of penalties and be clamped to `0/100`, even when OSV reported zero disclosed vulnerabilities.

This release replaces that behavior.

## Changed

- Disclosed vulnerabilities now carry the strongest dependency-health penalties.
- Deprecated packages, missing maintainer metadata, stale publishing activity, and outdated versions are scored as separate signals.
- Major, minor, and patch-level version gaps now receive different weights.
- Patch-level update lag receives a minimal fractional penalty.
- Freshness penalties are capped at 15 points.
- Maintenance penalties are capped at 20 points.
- Deprecation penalties are capped at 40 points.
- Outdated packages alone can no longer reduce dependency health to zero.
- `toolip score` now prints the dependency-health penalty breakdown.
- `toolip score --json` now returns structured score and penalty details.

## Fixed

- Fixed the reproduced case where Toolip reported `Dependency Health: 0` despite having zero disclosed vulnerabilities.
- Removed the assumption that an outdated package is equivalent to a medium-severity security vulnerability.
- Added regression coverage using the exact pattern of 11 outdated dependencies that exposed the flaw.

## Verification

- TypeScript typecheck passed.
- Complete test suite passed.
- Clean production build passed.
- Changelog verification passed.
- npm tarball validation passed.
- Isolated package installation passed.
- CLI version, self-test, help, and score command checks passed.

Built by Ashibuogwu Williams (`wbizmo`).
