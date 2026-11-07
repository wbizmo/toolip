# Python dependency inventory

Toolip reads Python project metadata without running Python, package managers,
build backends, or project hooks. It uses exact package records from
`uv.lock`, `poetry.lock`, or `Pipfile.lock`. The TOML parser is bounded by the
shared dependency-file size limit. `pyproject.toml` declarations provide root
dependency edges and retain markers, extras, optional groups, and development
classification when matching the lock graph.

uv workspace packages with safe relative `editable` or `directory` sources are
kept as local workspace identities. They participate in graph relationships
but are not sent to OSV as public PyPI releases. Lock entries from a registry
other than the public PyPI index, malformed source identities, and ambiguous
marker/version matches remain unknown or incomplete. Toolip does not infer an
installed package from a range alone. When a lock contains exact records,
supported PEP 440-style constraints are matched against those records and an
edge is created only if exactly one compatible instance remains in the
applicable marker and extras context. The range never becomes a package
version; unsupported specifiers and ambiguous matches stay unresolved.

`requirements*.txt`, `constraints*.txt`, and their `.in` inputs are parsed
without executing pip. Relative `-r` and `-c` includes are followed only
inside the project root, with cycle, depth, file-count and byte limits. Exact
unhashed pins remain `declared-pin`, not proof of an installed environment.
Exact hashes from pip-tools output on the public PyPI index produce
lock-confidence identities; hashes, extras and markers are part of the
identity so incompatible target variants do not collapse. Constraint-only
files never create installed package identities. Custom indexes and
unsupported requirement options remain provenance-unknown and are withheld
from public OSV queries. Ranges and unresolved includes/options remain
incomplete rather than becoming guessed versions.
Index configuration is evaluated across the complete include closure: a
custom or extra index in a parent file also makes hashed pins in included files
provenance-unknown, so those package names are not sent to the public PyPI OSV
endpoint.

For uv workspaces, Toolip follows only the root `tool.uv.workspace.members`
patterns and exclusions captured in the same immutable snapshot. Each member
`pyproject.toml` must declare a project name and match exactly one editable
workspace record in `uv.lock`; its requirements then link to unique compatible
lock instances from that member. Invalid or unmatched member patterns,
manifests, and workspace identities produce incomplete coverage. Discovery
does not follow symlinks or treat arbitrary nested Python projects as members.
Member glob matching uses bounded dynamic programming (`O(P·D)` per pattern,
where `P` is pattern length and `D` is the member path length), with one global
work cap and `O(D)` temporary space; it does not compile repository patterns
into backtracking regular expressions.

This does not expand Python targets or prove which markers/extras were active
in a particular runtime environment. A full Python-version/platform matrix
remains unsupported; those limits stay explicit in graph coverage.
