# PHP and Composer inventory

Toolip reads `composer.lock`, the root `composer.json`, and Composer `path`
repositories without invoking Composer, project scripts, plugins, Laravel
artisan commands, or PHP build steps. The project profile identifies PHP and
Laravel from source files, Composer requirements, and the conventional Laravel
entry points.

Composer lock entries retain exact Packagist name and version, production or
development classification, and dependency edges. PHP and `ext-*` / `lib-*`
platform requirements are not treated as third-party packages. Root and
transitive version constraints are checked against the locked version; an
incompatible or ambiguous match remains unresolved and makes graph coverage
incomplete.
Branch labels and other non-semver lock versions such as `dev-main` remain in
the dependency graph with unknown resolution confidence. They are not queried
as if they identified immutable released packages.

For configured path repositories, Toolip inspects at most 128 repository
patterns, 5,000 Composer manifests, and 50,000 directory entries, does not follow directory symlinks, and reads
each manifest through the bounded dependency reader. In-repository packages
with exact stable versions become workspace identities and contribute local
dependency edges. Branch aliases such as `dev-main`, invalid versions,
unsupported path patterns, missing manifests, and paths outside the project
remain explicitly unverified or incomplete. A local workspace identity is not
sent to OSV as a third-party package.

This is a read-only project profile and dependency inventory. It does not
execute Composer plugins or scripts, install dependencies, or apply
Laravel-specific code rules.
