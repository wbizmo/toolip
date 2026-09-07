# Dependency Upgrade Pull Requests

Preview an upgrade first:

```bash
toolip upgrade-pr express 5.1.0 --dry-run
```

Create the pull request:

```bash
toolip upgrade-pr express 5.1.0
```

## Transactional workflow

Toolip v2.2.0 performs upgrade mutations in a temporary Git worktree instead of switching/mutating the caller's current worktree.

The flow is:

1. Validate the requested package/version before mutation.
2. Resolve the project's package manager.
3. Allocate a collision-safe Toolip upgrade branch.
4. Create a temporary Git worktree for that branch.
5. Update the manifest/lockfile inside the temporary worktree.
6. Run the configured project tests.
7. Commit and push only after validation succeeds.
8. Open the pull request through the authenticated `gh` CLI.
9. Remove the temporary worktree in cleanup, including failure paths.

The caller's active branch and dirty files remain untouched throughout this process.

## Package managers

Toolip selects lockfile/update behavior from the project instead of always running npm commands. Current upgrade handling supports npm, pnpm, and Yarn project conventions.

## Safety guarantees

- invalid target versions are rejected before mutable work begins
- existing dirty files are preserved
- the user's active branch is not switched
- failed installs/tests/push/PR creation do not strand the user in the generated branch
- temporary worktrees are cleaned up in `finally` paths
- branch-name collisions are handled deliberately
- `--dry-run` does not mutate project files

Remote GitHub operations remain opt-in and use the user's existing `gh` authentication.
