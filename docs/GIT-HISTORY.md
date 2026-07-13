# Git History Secret Scanning

Toolip scans added lines across local Git history.

## Command

```bash
toolip git-history
toolip git-history --max-commits 5000
```

Evidence is redacted and fingerprinted. A historical secret must still be rotated even if it was later deleted from the working tree. Toolip does not automatically rewrite Git history.
