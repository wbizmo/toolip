# Go dependency inventory

By default, Toolip reads Go module metadata without invoking `go`, downloading
modules, or running project code. It discovers root and `go.work` member
`go.mod` files, reads `go.sum` records, and can use `vendor/modules.txt` plus
bounded captured Go import files to identify vendored package instances and
import edges.

Requirements in `go.mod` are not treated as selected versions: they are marked
unknown and are withheld from OSV queries because Go Minimal Version Selection
can choose a higher version. When the caller explicitly enables
`--allow-go-tool-execution` on `toolip scan` or `toolip sbom`, Toolip copies the
captured `go.mod` and `go.work` files into a private temporary tree, keeps the
project's captured `go.sum` records for comparison, and lets the isolated Go
tool create fresh checksum records. It runs `go list -m -json all` and `go mod
graph` with a 90-second deadline, isolated Go caches, bounded output, the
official Go module proxy and `sum.golang.org`. It never imports, builds, or
executes project source. The selected Go executable must resolve outside the
project and temporary tree and identify itself as the Go module tool. The
selected version is trusted only when the Go tool
returns a valid exact identity and its fresh Go module-file checksum matches
the authenticated checksum record and any captured project checksum.
Standalone modules use a private `-mod=mod` setting so Go can create fresh
checksum records when the snapshot omits `go.sum`; workspace mode omits that
incompatible flag and reads generated records from the isolated `go.work.sum`.
Replacements without independently verifiable external identities, checksum
mismatches, unresolved graph edges, unavailable tooling, and budget failures
remain unknown and keep the analysis incomplete. `--offline` cannot be
combined with Go tool execution.

Vendored modules use the exact versions recorded in `vendor/modules.txt`, but
are reconciled against all captured workspace `go.mod` requirements. A selected
vendor version below a declared requirement, an explicitly excluded version,
an ambiguous duplicate module path, or an unmatched requirement is incomplete;
local and remote replacement identities remain unknown. `vendor/modules.txt`
package paths are checked against vendored file directories, and vendored
imports are selected from the captured source snapshot. These checks do not
prove that the vendor files match the original module archive. Vendor artifact
integrity is therefore `unavailable`, not verified, and the inventory keeps an
explicit content-integrity warning. A matching captured `go.sum` archive hash
is carried as `declared-not-verified`; absent or conflicting hashes remain
unavailable. Offline inventory does not authenticate `go.sum` against the
checksum database or hash vendored files against an upstream archive.

Both `go.mod` and `go.work` replacement directives are recognized. In the
opt-in MVS path, a remote replacement is queried under its actual module path
and version only after its checksum is verified; local or unresolved
replacement targets remain `unknown` and are withheld from public OSV queries.
Workspace paths that escape the project are rejected. Use
`toolip scan --go-target '<json>'` or `toolip sbom --go-target '<json>'` to
select one target. The bounded JSON profile requires `id`, `goos`, `goarch`,
and `cgo`; it optionally accepts `goVersion` and up to 128 custom `tags`,
including explicit architecture-feature levels such as `amd64.v3`. The
serialized profile is limited to 4 KiB. For example:

```sh
toolip scan --go-target '{"id":"linux-amd64-go124","goos":"linux","goarch":"amd64","cgo":false,"goVersion":"1.24","tags":["enterprise"]}'
```

The scanner selects GOOS/GOARCH filename suffixes, `//go:build` expressions,
legacy `// +build` lines, cgo/custom tags, and known OS implications. Go release
tags require a supplied Go version. Architecture-feature constraints without a
declared feature level remain unknown. Test-only `*_test.go` imports are not
runtime edges. Missing targets, unsupported expressions and contradictory
modern/legacy constraints leave the source graph incomplete. A target ID is
included on selected dependency identities and edges; Toolip does not union
Windows, macOS and Linux imports into one target graph.

Strict offline scans perform no Go command or network access. Tool execution
is an explicit user choice and may disclose public module paths to the official
Go proxy and checksum database. These limits are visible in inventory warnings
and must not be interpreted as a complete vulnerability result.

For `F` captured Go source files, `B` source bytes, `P` manifest package paths,
`M` module instances and `E` import edges, vendored parsing is bounded by file
and byte limits. Sorting costs `O(F log F + M log M)`; path-trie indexing and
package-directory construction cost `O(B + F + P + M)`. Import ownership uses
longest-prefix lookup over path segments and graph output sorting costs
`O(E log E)`, giving `O(B + F log F + M log M + P + E log E)` time. Peak
additional space is `O(F + P + M + E)` for sorted paths, directory/module
indexes, manifest entries and edges; source text is read one file at a time
under the existing per-file and total-byte limits. Target profiles are at most
4 KiB, with at most 128 custom tags; build expressions are at most 4 KiB/512
tokens and are evaluated only for captured source files. The manifest-to-file
check uses a directory set, avoiding a repeated full vendor-file scan per
manifest package.

The explicit MVS path copies at most 5,000 metadata files and 32 MiB, accepts
at most 16 MiB of output per Go command, and gives the isolated Go process a
90-second deadline, two scheduler threads and a 768 MiB Go heap target. Toolip's
post-processing is `O(M + E log E)` time and `O(M + E + B)` space for `M`
module records, graph edges, and copied metadata. The Go tool's internal work
is independently capped by that process deadline and heap target; the measured
graph size and actual Go runtime remain environment-dependent.
