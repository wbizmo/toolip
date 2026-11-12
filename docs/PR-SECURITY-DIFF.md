# Pull request security diff

`toolip pr-scan <base> [head]` resolves both inputs to immutable commits before
reading the diff. It parses NUL-delimited Git change metadata, reads bounded
blobs by object ID, and compares the changed paths against the baseline. Renames
retain their path identity for comparison. Secret and supported source/config
rules run against the whole changed file so analyzers keep the context they
need; the report includes exact head-side changed-line ranges and separates
introduced, fixed and unchanged findings. JSON output is sanitized and SARIF
contains only introduced findings. JSON also includes up to 500 safe
`inlineReviewComments` for introduced findings whose reported line is inside a
changed hunk. Their static message omits source, evidence and provider text;
`inlineReviewCommentsTruncated` makes the output cap explicit. These are
review-ready records for a caller to consume; Toolip does not post comments to
GitHub or any other remote service.

```sh
toolip pr-scan origin/main HEAD --path . --json --sarif toolip-pr.sarif
```

For a GitHub workflow, `--github-event` binds the scan to the exact base and
head commit SHAs in the runner's pull request event file and checks that the
event targets `--github-repository`:

```sh
toolip pr-scan --github-event "$GITHUB_EVENT_PATH" \
  --github-repository "$GITHUB_REPOSITORY" --path . --json \
  --sarif toolip-pr.sarif
```

The event reader accepts only a regular, non-symlink JSON file up to 1 MiB,
rejects duplicate keys and unsupported actions, and exposes only the repository,
PR number and exact base/head SHAs needed for the scan. The Git object database
must already contain both commits; the command does not fetch refs or contact
GitHub. It does not execute PR content or post comments/checks. Keep workflow
permissions read-only for scanning, and do not use `pull_request_target` to
check out untrusted code.

The default gate exits 2 for introduced high or critical findings. `--fail-on`
accepts `critical`, `high`, `medium`, `low`, `info` or `none`. Incomplete scans
exit 3, including changes to dependency manifests/lockfiles, symlinks,
submodules, binary/non-UTF-8 content, unrecognized file types, execution
entrypoints/source files whose cross-file malicious-content graph was not run,
Docker/IaC/workflow files whose specialized analyzer was not run, and changed
files that exceed file or aggregate byte budgets. Invalid refs and failed Git
reads are errors. Cancellation is forwarded to Git subprocesses.

Dependency-change detection covers npm, pnpm and Yarn manifests/locks, Python
requirements and lock files, Go modules/workspaces/vendor manifests, Cargo,
Composer, Maven and Gradle inputs, plus their package-manager configuration
files. When one changes, the scanner reads the exact base and head dependency
input blobs from their Git trees and reports added, removed and version-changed
resolved package instances. Tree enumeration and blob parsing have explicit
entry, file and byte limits; malformed, symlinked, unsupported or over-budget
inputs leave the comparison incomplete.

Advisory recomputation is an explicit network opt-in. Add
`--online-advisories` to query OSV only for changed exact package instances;
public scoped npm names require the additional `--allow-public-scope` consent.
The query set is deduplicated and capped at 2,000 exact ecosystem/name/version
identities. Provider errors, withheld identities, malformed or truncated
responses, and output-budget exhaustion remain incomplete. Each 500-query
response is capped at 8 MiB, and the batches run sequentially. The report lists
introduced and fixed advisory identities per install path. Default invocation
makes no advisory-provider request and reports `not-recomputed`.

This feature is always `partial` at best: it analyzes changed paths, does not
produce a repository-wide clean result, and does not yet recalculate license,
provenance, maintainer-health, policy or reachability impacts for dependency
graph changes. These missing dimensions each receive a separate incomplete
reason code. Policy-file edits also report `policy-effects-not-recomputed`.
Deletions and renames are checked on both old and new paths, so removal of an
entrypoint, editor task, workflow, Dockerfile or IaC input cannot appear fully
covered. If the caller does not opt into online OSV queries, the JSON result
names advisory state as `not-recomputed`; if a provider or privacy gate
prevents a requested comparison, it reports `incomplete`. Dependency changes
remain explicitly incomplete and require a full scan. The diff scanner also
does not substitute for the malicious execution graph or specialized
Docker/IaC/workflow analysis; affected changes carry explicit incomplete
reason codes and cannot be accepted as a clean gate.
The existing staged pre-commit path separately reads staged Git index blobs, so
partial staging is evaluated from exactly the content that would be committed.
The scan never checks out or executes project code.

Finding reconciliation previously split and normalized the full file once
per finding, taking O(N × B_f) time for N findings in a changed file of B_f
bytes. It now fingerprints each normalized line once and keys findings by
rule, path, line-context fingerprint, evidence fingerprint and same-key
occurrence ordinal. This takes O(B_f + N) time, with O(B_f + N) temporary
space while that blob is processed. Evidence fingerprints and occurrence
ordinals keep multiple distinct findings in the same context from collapsing.

For the whole diff scan, let T be Git tree entries, L be dependency-input
bytes across the two snapshots, C be changed paths, G be bounded raw diff and
hunk bytes, B be changed-blob bytes, A be analyzer work, V/E be dependency
graph vertices/edges, Q be deduplicated changed package identities queried,
and N be findings. Worst-case time is O(T + L + C + G + B + A + V + E + N +
Q log Q + V log V). Additional space is O(T + L + C + G + B + V + E + Q + N),
including both concurrently compared dependency snapshots and finding maps.
Optional OSV work is bounded to 2,000 identities and four sequential batches
of at most 500 queries with an 8 MiB response cap per batch. Hard limits are
100,000 tree entries, 512 dependency inputs per snapshot, 2,000 changed files,
2 MiB per changed blob and 64 MiB of Git/blob output. Git tree, diff and blob
subprocesses have 30-second deadlines. Output never upgrades diff-only
coverage to a complete repository result.
