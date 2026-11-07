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
retain an explicit content-integrity warning because that manifest and the
checked-in source tree do not prove the checksum of the original module
archive.

Both `go.mod` and `go.work` replacement directives are recognized. In the
opt-in MVS path, a remote replacement is queried under its actual module path
and version only after its checksum is verified; local or unresolved
replacement targets remain `unknown` and are withheld from public OSV queries.
Workspace paths that escape the project are rejected. Import files with build
constraints are retained as incomplete because static inventory does not
select the active GOOS, GOARCH, or build-tag configuration.

Strict offline scans perform no Go command or network access. Tool execution
is an explicit user choice and may disclose public module paths to the official
Go proxy and checksum database. These limits are visible in inventory warnings
and must not be interpreted as a complete vulnerability result.

For `F` captured Go source files, `B` source bytes, `P` resolved module
instances and `E` import edges, vendored source parsing is bounded by configured
file and byte limits and uses indexed module-prefix matching. It runs in
`O(B + F log F + E log P)` time and `O(F + P + E + B)` peak additional space,
including sorted file/module indexes and the bounded captured source text.

The explicit MVS path copies at most 5,000 metadata files and 32 MiB, accepts
at most 16 MiB of output per Go command, and gives the isolated Go process a
90-second deadline, two scheduler threads and a 768 MiB Go heap target. Toolip's
post-processing is `O(M + E log E)` time and `O(M + E + B)` space for `M`
module records, graph edges, and copied metadata. The Go tool's internal work
is independently capped by that process deadline and heap target; the measured
graph size and actual Go runtime remain environment-dependent.
