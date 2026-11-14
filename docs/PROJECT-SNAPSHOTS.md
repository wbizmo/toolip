# Project snapshots and incremental analysis

This document describes the implementation on the combined Batches 07–16
branch. The public npm package is still `toolip@2.2.1`; the v3.2.1 work remains
in Draft PR #104 and has not been released.

## Execution model

One `ScannerContext` owns bounded file discovery for a scan. A frozen
`ProjectSnapshot` captures canonical relative paths, filesystem identities,
content SHA-256 values, lock/config digests and the content needed by analyzers.
The scorecard passes the same context and snapshot to Security Doctor,
dependency resolvers, analyzers and report builders. Snapshot-backed
dependency readers do not reopen or rediscover lockfiles. Snapshot reads use
the configured file/byte budgets; concurrent `TextFileReader` callers share
file and byte reservations and are limited to 8 active reads by default (hard
maximum 32).

`createProjectSnapshot(root, { previous, discoveredFiles, signal, ... })` can
reuse a previous file only when the root, canonical relative path, device/inode,
nanosecond timestamps and size still match. A reused snapshot is immutable.
Otherwise Toolip reads through a no-follow handle, verifies file identity and
content stability, and hashes the exact bytes. A changed or unreadable input
does not become a clean scan.

## Incremental invalidation

The watch command keeps a previous snapshot and one in-memory
`AnalysisResultCache` for the lifetime of the process. AST project-cache chunks
are keyed by stable file identity, content, local import component and
transitive dependency digests. Editing a helper invalidates its import
component and importers; unchanged independent components can reuse prior
findings. Rule, configuration and trusted-policy inputs are part of analyzer
scopes; lockfile bytes are captured in the same snapshot and included in
dependency analysis identities.
The generic `runIncrementalTaskDag` additionally requires explicit task input
fingerprints and hashes exact serialized dependency outputs; a dependent can
reuse its result when an upstream task reruns but produces identical bytes.

The cache is only an optimization. Corrupt, incomplete, oversized, evicted or
ambiguous entries are discarded and recomputed. It defaults to 10,000 entries
and has a hard maximum of 100,000, 64 MiB of serialized payload plus UTF-8
keys, and 4 MiB per entry.
Those byte counters do not include V8 map/buffer overhead or caller-owned task
outputs. The scheduler therefore documents task output size `R` separately
from retained cache bytes.

## CLI and TypeScript integration

Existing `scan`, `scorecard` and `doctor` command invocations remain valid;
snapshot creation is internal and adds no required CLI flags. `toolip watch`
uses the previous snapshot/cache automatically. `toolip watch --once` captures
one snapshot and exits. Cache state is process-local and is never written to
the repository, so there is no persistent cache migration or trust file to
manage.

The implementation helpers live under `src/application` and are not exposed
as a stable package-level API in the currently published v2.2.1 package. A
TypeScript integration inside this source tree passes one `ScannerContext`,
one `ProjectSnapshot`, the same `AbortSignal`, and an optional shared
`AnalysisResultCache` into `buildSecurityScorecard` or `runSecurityDoctor`.
Callers must use a stable project root/scope, include all analyzer-relevant
configuration in the scope or input fingerprint, and treat incomplete coverage
as unknown. `runIncrementalTaskDag` callers must provide a content/config
fingerprint for each task whose own inputs can change independently.

## Budgets and cancellation

The DAG scheduler accepts at most 100,000 tasks, 1,000,000 dependency entries,
16 MiB of task/dependency ID metadata, 16 MiB of version/fingerprint metadata,
and 32 concurrent tasks. Cache keys and IDs are individually bounded. An abort
signals active tasks, marks queued tasks cancelled, waits for active cleanup,
and removes the abort listener. Queued file reads are removed when cancelled;
active reads release their file/byte reservations and close handles in
`finally` blocks. These limits bound scheduler structures and retained cache
state, not all transient TypeScript compiler/runtime memory or caller output.

Cold/warm/incremental and simultaneous-scan evidence, including observed reads,
cache counters, wall time, heap and RSS, is recorded in
[`BENCHMARKS.md`](BENCHMARKS.md). Measurements are synthetic local Linux
evidence, not release qualification or a whole-process memory proof.
