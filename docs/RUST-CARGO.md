# Rust and Cargo dependency inventory

Toolip reads Cargo.lock v3/v4 as data; it never invokes Cargo, build scripts,
procedural macros, or project code during inventory. Package identities require
a valid Cargo crate name and semantic version; malformed names, versions, or
dependency entries make coverage incomplete rather than creating an advisory
identity. Registry packages from the official crates.io index require a
lockfile SHA-256 checksum before they are queried as resolved third-party
dependencies. That checksum is declared lock data, not independent
verification of downloaded crate bytes or checksum-database inclusion. Git and
unresolved path sources remain provenance-unknown and are withheld from OSV
queries.

For a declared Cargo workspace, Toolip matches captured `Cargo.toml` member
manifests to exact package name/version identities in Cargo.lock, records
workspace membership and direct dependency edges, and retains requested
features and target `cfg` expressions where manifests declare them. Package
`declaredFeatures` are the names defined by the manifest; they are not a claim
that Toolip resolved the active Cargo feature set. Likewise, target-specific
manifest entries describe declared contexts, not the host-target selection.
When feature or target selection cannot be established from lock data, the
inventory emits `cargo-active-feature-target-selection-unverified` and marks
coverage incomplete.

Workspace patterns are matched against the immutable file snapshot, with
bounded manifest counts and traversal depth. Missing, malformed, excluded,
unmatched, or ambiguously locked members produce explicit warnings. Cargo.lock
entries with duplicate package versions or aliases retain separate identities;
only an unambiguous exact requirement/path is connected. Unsupported lockfile
versions do not fall back to manifest ranges as installed packages.

This inventory is offline and does not execute `cargo metadata`. It can report
exact locked package identities and OSV advisories, but it does not verify
crates.io checksum-database inclusion, Git commit signatures, path-source
contents, or the safety of signed package contents. Those states remain
unknown and must not be read as a clean trust verdict.
