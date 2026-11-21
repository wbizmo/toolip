# PHP and Composer inventory

Toolip reads `composer.lock`, the root `composer.json`, and Composer `path`
repositories without invoking Composer, project scripts, plugins, Laravel
artisan commands, or PHP build steps. The project profile identifies PHP and
Laravel from source files, Composer requirements, and the conventional Laravel
entry points.

Composer lock entries retain exact Packagist name and version, production or
development classification, and dependency edges. PHP and `ext-*` / `lib-*`
platform requirements, including Composer's own runtime/plugin API packages,
are not treated as third-party packages. Package names and requirement records
are validated before graph resolution. A platform-only lock with empty package
sections is a complete empty graph. Root and
transitive version constraints are checked against the locked version; an
incompatible or ambiguous match remains unresolved and makes graph coverage
incomplete.
Composer lock aliases are used to connect branch packages to compatible root
and transitive constraints. The installed identity stays at the locked branch
version (for example, `dev-main`) with unknown resolution confidence, so the
alias is never queried as an immutable Packagist release. Inline root aliases
such as `dev-bugfix as 1.0.x-dev` are recognized for matching without changing
the locked package identity. Alias records are limited to 10,000 per lock and
8 per package; lock package records are limited to 100,000 and package/root
dependency requirement sections to 10,000 entries each. Exceeding a budget or
using malformed alias data makes coverage incomplete.

`composer.json` `config.platform` settings are compared with the lock's
`platform-overrides` values. Invalid or stale settings mark Composer lock
packages unknown and withhold them from public OSV queries. Composer package
license metadata is retained in SBOMs: SPDX expressions are validated and
Composer's disjunctive license lists become an SPDX `OR` choice; names such as
`proprietary` remain named CycloneDX licenses and are `NOASSERTION` in SPDX.
Invalid or over-budget license arrays are omitted with a warning rather than
copied into the SBOM.

Branch labels and other non-semver lock versions such as `dev-main` remain in
the dependency graph with unknown resolution confidence even when their aliases
resolve graph edges.

For configured path repositories, Toolip inspects at most 128 repository
patterns, 5,000 Composer manifests, and 50,000 directory entries, does not follow directory symlinks, and reads
each manifest through the bounded dependency reader. In-repository packages
with exact stable versions become workspace identities and contribute local
dependency edges. Branch aliases such as `dev-main`, invalid versions,
unsupported path patterns, missing manifests, and paths outside the project
remain explicitly unverified or incomplete. A local workspace identity is not
sent to OSV as a third-party package.

Non-path custom repositories do not establish public Packagist provenance.
When the root Composer manifest configures an unknown/custom repository, or is
missing beside a lockfile, non-path lock packages remain present but have
unknown resolution confidence and are withheld from public OSV queries. Only
the implicit/default Packagist origin, or the explicit official HTTPS endpoint
`repo.packagist.org`, keeps that public query path. Repository URLs and
credentials are never copied into inventory warnings or source labels. Path
lock URLs must be project-relative; URI schemes, absolute paths and traversal
paths remain unverified.

This is a read-only project profile and dependency inventory. It does not
execute Composer plugins or scripts, install dependencies, or apply
Laravel-specific code rules.

The lock alias and platform override fields follow Composer's current
[`Locker` schema](https://github.com/composer/composer/blob/main/src/Composer/Package/Locker.php),
the [alias documentation](https://getcomposer.org/doc/articles/aliases.md),
and the [`config.platform` documentation](https://getcomposer.org/doc/06-config.md#platform).
