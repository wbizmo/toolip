# Python dependency inventory

Toolip reads Python project metadata without running Python, package managers,
build backends, or project hooks. It uses exact package records from
`uv.lock`, `poetry.lock`, `Pipfile.lock`, and supported `requirements*.txt`
inputs. The TOML parser is bounded by the
shared dependency-file size limit. `pyproject.toml` declarations provide root
dependency edges and retain markers, extras, optional groups, and development
classification when matching the lock graph.

Pipenv root `[packages]` and `[dev-packages]` entries are matched to exact
`Pipfile.lock` versions using PEP 440 constraints. Lock sources are sent to
public PyPI only when the named Pipenv index resolves to the public PyPI HTTPS
endpoint with `verify_ssl = true`; credential-bearing or custom source URLs are hashed in internal
identity keys and remain unknown. Valid Pipenv hashes are retained as declared,
not verified bytes. Pipenv's lock format does not carry a complete dependency
edge graph, so Toolip reports that graph as incomplete while retaining exact
locked identities and root edges.

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

Use `toolip scan --python-target '<json>'` or
`toolip sbom --python-target '<json>'` to resolve one explicit target. The
bounded JSON object accepts `id`, all of the PEP 508 marker environment keys
(`implementation_name`, `implementation_version`, `os_name`,
`platform_machine`, `platform_python_implementation`, `platform_release`,
`platform_system`, `platform_version`, `python_full_version`, `python_version`,
and `sys_platform`), plus an optional `extras` array. The serialized profile is
limited to 4 KiB, environment values to 256 characters, 64 extras, and each
extra to 128 characters. For example:

```sh
toolip scan --python-target '{"id":"py312-linux","environment":{"implementation_name":"cpython","implementation_version":"3.12.2","os_name":"posix","platform_machine":"x86_64","platform_python_implementation":"CPython","platform_release":"6.8.0","platform_system":"Linux","platform_version":"test-release","python_full_version":"3.12.2","python_version":"3.12","sys_platform":"linux"},"extras":["fast"]}'
```

The marker evaluator supports bounded PEP 508 boolean expressions, comparisons,
`in`/`not in`, and Python version ordering. Unsupported markers, dependency
groups that need package-manager-specific context, and missing target data stay
unknown and make coverage incomplete. uv/Poetry lock records carrying group
membership are currently withheld because the target profile does not select
dependency groups; Poetry group declarations do not become root edges based on
the unrelated `extras` selector. A target produces one selected graph;
Toolip does not union Linux, Windows, Python-version, or extra variants into a
single installed graph. Selected target IDs are carried into dependency edges
and CycloneDX properties so downstream OSV/SBOM consumers can preserve scope.

Declared hashes are not proof that Toolip received or hashed artifact bytes.
Python hash status is `declared-not-verified` when a lock/requirements record
contains hashes and `unavailable` when it does not; the current static inventory
does not verify a wheel against an installed file or trusted download.
Unverified ranges, private/custom indexes, editable/local sources and ambiguous
target candidates remain unresolved or withheld from public advisory queries.
