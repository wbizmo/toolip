# Dependency Upgrade Pull Requests

Preview an upgrade first:

```bash
toolip upgrade-pr express 5.1.0 --dry-run
```

Create the pull request:

```bash
toolip upgrade-pr express 5.1.0 --allow-project-tests
```

Project tests are repository-controlled commands. They are never run unless
`--allow-project-tests` is supplied explicitly, even though dependencies are
installed with lifecycle scripts disabled. Review the target repository before
granting that permission. `--dry-run` does not run tests and does not require
the flag.

## Transactional workflow

Toolip performs upgrade mutations in a temporary Git worktree instead of switching or mutating the caller's current worktree.

The flow is:

1. Validate the requested package/version before mutation.
2. Resolve the project's package manager.
3. Allocate a collision-safe Toolip upgrade branch.
4. Create a temporary Git worktree for that branch.
5. Reject dirty package manifests or lockfiles, then install the baseline lock graph with lifecycle scripts disabled.
6. Run Toolip's bounded baseline security assessment and preserve its policy findings.
7. Update the manifest/lockfile inside the temporary worktree and confirm the exact requested direct version appears in the resolved graph.
8. Install the candidate lock graph with lifecycle scripts disabled.
9. Run configured project tests only after explicit approval, then run Toolip's candidate assessment and a fail-closed policy comparison.
10. Reject incomplete scans, a target version that is not reported as a fix for an existing advisory, any target advisory that remains, and any new policy-blocking finding.
11. Verify that only the package manifest and manager lockfile changed, and check the diff before creating a commit.
12. Commit and push only after all validation succeeds, then open a pull request through the authenticated `gh` CLI.
13. Remove the temporary worktree in cleanup, including failure paths. If PR creation returns an error after a push, query GitHub for any open or closed PR using that branch; delete the remote branch only after a successful query confirms none exists. Keep it when the query is unavailable or malformed, since the PR may have been created before the CLI failed.

The caller's active branch and dirty files remain untouched throughout this process.

## Package managers

Toolip selects lockfile/update behavior from the project instead of always running npm commands. Current upgrade handling supports npm, pnpm, and Yarn project conventions.

## Safety guarantees

- invalid target versions are rejected before mutable work begins
- existing dirty files are preserved
- the user's active branch is not switched
- failed installs/tests/push/PR creation do not strand the caller in the generated local branch; a pushed branch is deleted only when GitHub confirms no PR uses it, and is preserved when PR creation status is ambiguous
- temporary worktrees are cleaned up in `finally` paths
- branch-name collisions are handled deliberately
- `--dry-run` does not mutate project files
- baseline and candidate scans must both complete; provider failures block PR creation
- repository policies cannot suppress findings or lower the built-in high-severity and complete-coverage gate
- the PR description contains only verification identifiers and counts, records remaining risks, and includes a rollback plan
- generated PRs always require human review and are never auto-merged
- package-manager and test processes receive a private temporary home and an
  allowlisted environment; host registry/GitHub/cloud credentials and
  `NODE_OPTIONS` are not inherited
- project package-manager configuration is checked before the first install;
  authentication overrides, non-public registries, Yarn plugins/shims and pnpm
  resolver hooks fail closed
- Git hooks are disabled for all temporary worktree operations

Remote GitHub operations remain opt-in and use the user's existing `gh` authentication.
Scoped package names are withheld from public providers unless
`--allow-public-scope` is supplied. A custom `--policy-file` may tighten the
comparison; repository suppressions are not trusted for this operation.

## Bounds and complexity

Each baseline/candidate assessment uses Toolip's existing limits for files,
bytes, analyzer work, provider concurrency and deadlines. If `F` is discovered
files, `B` bounded source bytes, `V` dependency instances, `E` dependency edges
and `N` findings, each scorecard is `O(F log F + B + V + E + N log N)` time
with `O(F + B + V + E + N)` peak space, including deterministic path/result
sorting. The remediation comparison is `O(N)` time and `O(N)` space using
finding-key sets. Two scans keep the asymptotic bounds unchanged; baseline
findings remain resident while the candidate scorecard runs, so peak memory
includes both finding lists. The install/test subprocess buffer is capped at
8 MiB and each child has a five-minute timeout; provider analysis has a
three-minute deadline per scorecard.
