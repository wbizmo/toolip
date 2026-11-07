# Historical Security Tracking

Toolip stores versioned local scan history in `.toolip/history.json`.

## Commands

```bash
toolip history list
toolip history trend
toolip history clear
```

History entries may include timestamps, score, finding counts, Git branch, Git commit, dirty state, and finding fingerprints. History remains local and is intended to support regression tracking between commits.

Append and clear operations use the same cross-process directory lease as the vault. Each update is written to a unique same-directory temporary file, flushed, and atomically renamed. Appends with an existing entry ID are treated as retries and do not create duplicates. Retention is applied after each append. `clear` is serialized with append: entries appended before clear are removed, while entries appended after clear remain. If both run at once, the lock acquisition order defines this serial order. A crash during a write leaves the prior valid file or the fully renamed new file; orphaned temporary files are ignored.

The default retention limit is 500 entries. The history API accepts an explicit
limit from 1 through 5,000; `NaN`, fractional, zero, negative and larger values
are rejected. Reads and writes are capped at 32 MiB, and stored entry counts
above 5,000 are rejected. A history write that exceeds either budget fails
explicitly and does not replace the previous file. Private local-state reads
use bounded handle-based chunks and verify that the open file and named path
remain the same and unchanged for the duration of the read.

The `.toolip` directory is required to be a real current-user-owned directory on POSIX systems and is repaired to mode `0700`; history files are opened without following a final symlink and repaired to `0600` through their handles. Windows uses inherited ACLs and the same atomic lease, without a claim that Node verifies DACL ownership or access rules.
