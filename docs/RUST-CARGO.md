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
manifests to exact package name/version identities in Cargo.lock and records
workspace membership, dependency aliases, requested features and target `cfg`
expressions. Static resolution covers default and optional dependency features,
`dep:` feature references, dependency feature requests (including weak `?/`
references), inherited workspace dependencies and feature unification among
captured workspace packages. Exact registry or Git source IDs retained in
Cargo.lock are used to avoid connecting same-name, same-version packages from
different sources.

Use `toolip scan --cargo-target <triple>` or
`toolip sbom --cargo-target <triple>` to select one Rust target. The bounded
`cfg(...)` evaluator handles `all`, `any`, `not`, direct target triples and
common target properties. It maps common aliases such as Android, ARM, WASI,
Darwin and embedded `none` targets to their Rust `target_*` values. Unknown or
unsupported expressions and target properties remain unresolved and make
coverage incomplete. With no explicit target, platform-specific dependencies
are retained conservatively and reported as unresolved rather than treated as
an exact host selection. The selected target is included in package identities
and SBOM provenance.

`declaredFeatures` lists feature names defined by a manifest;
`activeFeatures` records the statically resolved features for captured
workspace packages. Cargo.lock does not record activated features for
third-party registry packages, and their manifests are not fetched or executed
for this offline inventory. If a crates.io package is present,
`cargo-registry-feature-resolution-unverified` keeps coverage incomplete.
Unsupported Cargo feature syntax, missing workspace manifests, ambiguous lock
identities, unknown target contexts and exceeded work limits likewise produce
warnings and incomplete coverage.

Workspace patterns are matched against the immutable file snapshot, with
bounded manifest counts and traversal depth. Missing, malformed, excluded,
unmatched, or ambiguously locked members produce explicit warnings. Cargo.lock
entries with duplicate package versions or aliases retain separate identities;
source IDs disambiguate registry and Git edges, while an ambiguous exact
requirement/path remains unresolved. Unsupported lockfile versions do not fall
back to manifest ranges as installed packages.

This inventory is offline and does not execute `cargo metadata`. The committed
regression fixture was generated separately with a checksum-verified Cargo
toolchain using inert local workspace manifests and `cargo metadata --offline`;
no build scripts were run. The inventory can report exact locked package
identities and OSV advisories, but it does not verify crates.io
checksum-database inclusion, Git commit signatures, path-source contents, or
the safety of signed package contents. Those states remain unknown and must not
be read as a clean trust verdict.
