# Malicious content and pre-execution trust gate

## Current static analysis status

`toolip doctor` includes an experimental, non-executing malicious-content pass.
It recognizes root and workspace npm script entrypoints, VS Code tasks whose
`runOptions.runOn` is `folderOpen`,
tasks and their named task dependencies, tracked Husky hooks, GitHub Actions
inline and block-scalar `run` steps with their step/default working
directories, and selected JavaScript tool configuration imports. Workflow
commands that select a workspace by package name, package
path, npm `--prefix`, pnpm `--filter`, or Yarn `workspace` are resolved against
the exact package manifests in the captured tree; ambiguous or dynamic
selectors remain incomplete. Workspace package script paths are resolved from
their package directory. It also discovers supported interpreter shebangs independent of file
extension, and applies executable-text signatures only when paired with a
high-signal behavior pattern. It follows bounded local interpreter,
shell-source and import references, including disguised and extensionless files.
Signals include encoded evaluation, download-to-shell, credential-store access
paired with outbound transfer, archive extraction followed by execution, and
payload loading paired with startup-persistence changes. Signals are narrow
heuristics; findings identify behavior classes without retaining matching
source text, credentials or payload bytes. The shared
snapshot discovery includes present index-tracked files even when local ignore
rules match. Findings use the canonical `Finding` contract and include a static
trace without embedding source text or payload bytes. The bounded interpreter
reference list includes Node, Deno, Bun, Python, Ruby, Perl, PHP, POSIX shells,
PowerShell and Windows `cmd /c` or `/k`, with captured `.py`, `.rb`, `.pl`,
`.php`, `.ps1`, `.cmd` and `.bat` targets resolved without execution.

Unresolved references and malformed `package.json`, `.vscode/tasks.json`, or
workflow documents remain unknown/incomplete. GitHub Actions workflow files
are parsed as YAML with duplicate-key checks and a bounded alias-expansion
budget; malformed YAML, invalid run-command types, and unsupported workflow
structures fail closed. Known binary file types and
source maps are excluded; a binary snapshot with an unrecognized extension is
counted as eligible but skipped, so coverage becomes incomplete instead of
reporting a clean scan. Other content is subject to the shared per-file,
aggregate byte and file-count limits. The execution graph also caps entrypoints
at 10,000, references per entrypoint at 10,000, and traversed references at
100,000. Exceeding a cap marks analysis partial. Reports distinguish `TLP-MAL-001`
suspicious execution chains from `TLP-MAL-002` unresolved dynamic references.
These patterns are indicators for review, not proof that a repository is
malicious or safe.

The current pass is not a complete implementation of issue #95. It does not yet
cover all shell/PowerShell semantics, every CI provider, archive-contained
references, general magic-byte classification, robust parser diagnostics for
every configuration format, or calibrated false-positive/negative rates.
Credential and persistence patterns are deliberately narrow and do not model
all platforms or secret stores. Stage A classifies executable magic in changed
PR blobs as unsupported/incomplete; it does not disassemble or execute those
files. The shared analyzer caches path-neutral source signals and local
references in a bounded LRU keyed by exact content hash; a changed target gets a
new parsed node while unchanged content reuses its extracted node data. Path
edges and entrypoint traces are still rebuilt for each immutable snapshot, so
cached dependency-slice results remain to be completed.
Rename and PR-tree semantics are covered by Stage A separately. Do not treat
static non-observation as evidence that a repository is benign.

For the integrated repository analyzer, let F be candidate files, B the accepted text bytes, V the execution-reference nodes, and E the resolved edges. Snapshot discovery, sorting, hashing, content signatures, and classification are O(F log F + B); indexed reference traversal and signature reachability are O(V + E) and each are capped at 100,000 visits. Peak additional memory is O(F + B + V + E), bounded by 100,000 files, 256 MiB total text, 2 MiB per file, 10,000 entrypoints, and 10,000 references per entrypoint.

## Pre-execution gate status

The `Stage A Trusted Pre-execution Gate` workflow runs from the protected base
revision on `pull_request_target`. It checks out only that trusted base,
uses a self-contained scanner whose bundled YAML parser and gate source are
covered together by a SHA-256 pin in the trusted workflow. No dependency install
occurs before the exact PR trees and artifacts have been scanned. The scanner runs on
exact Node.js `24.22.1` (the runtime pin is checked against the supported engine
range) and fetches the event's PR merge ref into a temporary **bare Git
object database**. It never checks out PR files or runs repository code in this
workflow. It validates the base-to-head diff (including detected renames and
copies), checks the immutable merge parents, then scans the exact head and merge
trees. Changed entrypoints are traced through static local imports and common
interpreter invocations to unchanged files in each scanned tree. npm lockfiles
are checked for exact HTTPS npm registry origins, SHA-512 integrity and
manifest alignment. Every exact artifact in a supported npm lockfile is fetched
from the public registry, integrity-verified, and scanned in memory before
installation; checking only changed entries would leave unchanged install hooks
outside the gate. Scoped names are fetched only for explicitly allowlisted
public scopes. After content inspection, Stage A performs a scripts-disabled
`npm ci` in a temporary directory containing only the captured manifest and
lockfile, then verifies registry signatures and available provenance
attestations before Stage B. This is the only Stage A install and it consumes
only the captured PR manifest and lockfile after approval.
Unsupported scope policy, package-manager
lockfiles and archives also block Stage B.
The inspected tarball's embedded package name and exact version must match its
lock entry; npm aliases retain the registry package identity for this check and
for scope withholding. Tarball integrity alone cannot authorize mismatched
package metadata.
Missing/moved commits, malformed objects, submodules, escaping symlinks,
suspicious execution patterns, parser failures and exhausted size budgets block
or make the result incomplete.

Changed GitHub Actions workflows are additionally checked for immutable
third-party action commit pins, immutable Docker image digests, local action
usage and privileged `pull_request_target` triggers. An unpinned action or a
non-Stage-A `pull_request_target` trigger blocks the candidate. Local actions
and expanded workflow token permissions make Stage A incomplete and require
review before Stage B. Changes to `.github/CODEOWNERS`, the Stage A scanner,
its artifact writers/verifiers, runtime/workflow verifiers and trusted gate
workflow paths also require a current maintainer review through the base
branch's time-limited exception policy. The trusted scanner emits stable, redacted SARIF
results, concise execution-chain traces, workflow error annotations and a
one-day diagnostics artifact; incomplete coverage also receives a gate-level
SARIF result.

False-positive exceptions are opt-in and live in
`.toolip/stage-a-exceptions.json` on the trusted base revision, never solely in
the candidate head. Each version-1 entry names one stable finding ID or one
incomplete reason code, the exact head-tree input digest, a rationale, and an
ISO expiry no more than 30 days away. Matching covers findings and coverage
reasons from the exact head and merge Git blobs and inspected dependency
artifacts. A finding exception suppresses only that stable finding; a reason
exception suppresses only the matching reason class for that exact tree.
Artifact counts, integrity checks and required signature-audit coverage are
still enforced when the approval record is written, so an exception cannot
stand in for a required artifact inspection. An entry applies only after
GitHub reports a current-head `APPROVED` review from an `OWNER`, `MEMBER`, or
`COLLABORATOR` other than the PR author. Stale approvals, review-provider
failures, invalid policy, and expired entries do not suppress a finding. The
one-day approval artifact records the policy digest, exception ID, reviewer,
review time, head commit, and expiry for audit. Server-side branch rules and
CODEOWNERS still determine which reviews are required to merge.

Stage A also records GitHub's author-association, head-repository/fork context,
and exact head-commit signature-verification summary. Fork heads,
external-contributor associations, and unverified signatures emit explicit
maintainer-review warnings; missing or inconsistent author, repository, or
signature context makes the scan incomplete. Signature payloads are never
copied into findings. These signals do not label a contributor malicious and
do not replace independent-approval or signed-commit branch rules.

Example trusted-base policy shape (hashes are specific to the candidate):

```json
{
  "version": 1,
  "exceptions": [
    {
      "id": "reviewed-rule-false-positive",
      "findingId": "<64-character-stable-finding-id>",
      "headInputSha256": "<64-character-head-tree-digest>",
      "expiresAt": "2026-11-30T00:00:00.000Z",
      "rationale": "Why this exact reviewed finding is accepted temporarily."
    }
  ]
}
```

Only an `approved` scan reaches the artifact-writing step. The short-lived
artifact contains the scan identity (repository, PR number, base/head/merge
SHAs, run ID), scanner/input digests, coverage counts and complexity disclosure
result. `ci.yml` and `pr-quality.yml`
run from `workflow_run`, validate that artifact against the successful Stage A
run, and check out the **same immutable merge SHA** before starting Stage B.
Their tokens are read-only; no publishing/deployment credentials are provided.
Before any Stage B checkout or execution, the trusted verifier also queries the
current PR through GitHub's API and requires its open state, base branch, base
SHA, head SHA and merge SHA to equal the completed Stage A run. It also
recomputes the required complexity disclosure from the live PR body, so a
body-only edit cannot reuse stale review evidence. Stage A runs on `edited`
events, and delayed runs after a force-push, base update, body edit, close or
merge are rejected as stale. Each Stage B workflow performs that check using
only `pull-requests:read`. A failed, cancelled or otherwise non-successful
Stage A run produces an explicit failing Stage B verifier job; it is not
represented by skipped checks, which GitHub may treat as successful for
required-check purposes.
npm install, build, test and audit steps depend on the verified artifact. This
keeps PR checkout and execution out of the `pull_request_target` workflow.

The scanner reads exact Git objects with explicit file, tree, per-file and
aggregate byte limits and bounded `git cat-file --batch` reads. For F tree
entries, B scanned bytes, V reference nodes and E local-reference edges,
tree/diff ordering costs O(F log F), Git-object reads and pattern passes cost
O(F+B), graph construction costs O(B+V+E), and changed-entrypoint traversal
costs O(W), where W is capped at 1,000,000 visits with 1 MiB of trace output.
For K exact locked package artifacts, A downloaded bytes and U decompressed bytes,
integrity verification and tar scanning cost O(A+U); each archive is capped at
32 MiB compressed and 128 MiB unpacked, downloads use concurrency 4, and
aggregate archive bytes/files are bounded. Peak additional memory is
O(F+B+V+E+T+4A+U), with bounded tar content and 100,000 files. It reads both
head and merge trees, so Git object scanning uses two tree budgets. Synthetic
fixtures cover malicious scripts, malformed manifests, symlink escapes,
untrusted workflow interpolation, merge-parent identity, unusual-extension
text, unchanged targets reached from changed configs, rename detection, npm
tarball integrity, lifecycle hooks, traversal, checksum validation and
incomplete archive handling. The prior baseline measurement (277 entries, 235
text candidates, 979,203 bytes) predates this two-tree implementation and is
not a current benchmark.

This is an integrated Stage A boundary, but **issue #96 remains incomplete**.
The scanner uses bounded heuristics rather than a complete execution-chain
graph. Tarballs containing binary files, install lifecycle hooks, unsupported
entries or unapproved scopes remain incomplete. The scripts-disabled install
and registry signature/provenance check run only after exact lock entries and
tarball bytes pass the inert scan; any install or signature failure blocks
approval. Non-npm artifact provenance verification, force-push continuity, and
several #95 behaviors remain outside this implementation. A diff rename is only a path relationship and
does not prove semantic equivalence. Stage A `approved` means the implemented
bounded checks completed without a known signal; it is not proof that a
repository is benign. The former `evaluateStageA` helper remains a local model
and is not the CI authorization boundary.

The repository includes `.github/CODEOWNERS` entries assigning workflow,
Stage A scanner/artifact, Node runtime verifier and workflow-policy verifier
trust roots to `@wbizmo`. GitHub enforces those entries only when a ruleset
requires code-owner review. The repository owner must
separately configure and verify rulesets requiring the Stage A check and
independent reviews, restrict who can change those trust roots, and prevent
unreviewed force pushes. Those server-side controls have not been verified from
this local environment. A valid digest establishes scanner identity, not
benign behavior. The gate cannot stop already-running IDE tasks or a
compromised account pushing to an unprotected branch.

There is also a first-deployment boundary: GitHub loads a `pull_request_target`
workflow from the pull request's base branch. Because this combined PR adds
Stage A to `main`, that new workflow cannot gate this same first PR until its
trusted workflow has been merged into the base. This patch also changes CI,
PR Quality and CodeQL from `pull_request` to `workflow_run`; as a result, those
new Stage B listeners do not run for this first PR either, because the Stage A
workflow they listen for is not yet on the default branch. Do not assume the
old base-branch versions continue to provide checks after this PR changes those
workflow files. Stage A's local exact-tree fixtures and review are evidence for
the implementation, but they do not establish that GitHub ran or required
Stage A for this initial PR. The combined PR cannot bootstrap its own trusted
check. Keep it unmergeable until either an independently administered GitHub
App check is installed and required by the ruleset, or a separately reviewed
bootstrap change has introduced Stage A, the complete Stage B `workflow_run`
consumers and trusted verifiers on `main`. A
Stage A-only bootstrap is insufficient because GitHub loads `workflow_run`
listeners from the default branch too. In either case, the trusted scanner
must inspect this PR's exact commits before any Stage B job runs
project-controlled code, and the required checks must be observed on this exact
PR head. A manual merge exception, administrator approval in place of the
gate, or execution of the proposed workflow from the PR branch does not
satisfy this requirement.

Before relying on this gate, repository administrators should configure and
independently verify:

- A [repository ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
  targeting `main`, requiring the Stage A workflow, each Stage B `Verify
trusted Stage A result` job, and the downstream CI/PR Quality/CodeQL checks,
  with independent approval and restricted force-push/deletion rights. The
  verifier job must itself be required because dependent jobs are skipped when
  Stage A fails, and GitHub treats skipped jobs as successful.
- For this first PR, configure and test an independently trusted required
  check before considering merge. An alternative is a separately reviewed
  bootstrap change that adds Stage A, the Stage B consumers and their trusted
  artifact verifiers to `main`; its own validation must not execute the
  combined PR's code before the gate exists.
- [CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
  coverage for `.github/workflows/**`, `scripts/stage-a-gate.mjs`, and its
  artifact verifiers, with code-owner review required by the ruleset.
- [Signed-commit verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
  when required by repository policy, plus restricted push access to protected
  branches.
- [GitHub Actions repository controls](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
  that restrict allowed actions and prevent untrusted workflows from accessing
  secrets or write-scoped tokens.

These are host-side settings, not properties that a local scanner or this
workflow can enforce. A change to the Stage A or downstream Stage B trust-root
workflow is marked incomplete until an exact-tree, time-limited exception is
approved by a current maintainer; the GitHub ruleset remains the authoritative
merge control.
