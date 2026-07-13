# Historical Security Tracking

Toolip stores versioned local scan history in `.toolip/history.json`.

## Commands

```bash
toolip history list
toolip history trend
toolip history clear
```

History entries may include timestamps, score, finding counts, Git branch, Git commit, dirty state, and finding fingerprints. History remains local and is intended to support regression tracking between commits.
