# Dependency Upgrade Pull Requests

Run a dry run first:

```bash
toolip upgrade-pr express 5.1.0 --dry-run
```

Create a pull request:

```bash
toolip upgrade-pr express 5.1.0
```

Toolip creates a branch, updates the manifest and lockfile, runs tests, commits, pushes, and opens a pull request through the authenticated `gh` CLI.
