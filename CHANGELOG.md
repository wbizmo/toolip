# Changelog

All notable changes to Toolip are documented in this file.

The format follows Keep a Changelog principles, and Toolip uses semantic versioning.

## Unreleased

### Added

- Shared analyzer, finding, rule, report, and cache contracts for Toolip v2.
- Bounded analyzer orchestration with timeout and cancellation support.
- Cross-platform continuous integration.
- Release candidate verification from the packed npm artifact.
- Architecture, engineering, contribution, security, and release documentation.

### Changed

- Release verification now validates the exact tarball users will install.
- `package.json` remains the sole source of version truth.
- npm package contents are restricted to the compiled CLI and required documentation.

### Security

- Releases are blocked when the executable, README, license, shebang, or version synchronization is invalid.
