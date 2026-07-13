# Remote Repository Audit

Run:

```bash
toolip audit-repo https://github.com/owner/repository
```

The command uses the user's authenticated `gh` CLI, clones the public repository into a temporary directory, runs Toolip locally, and deletes the temporary clone.
