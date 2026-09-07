# Watch Mode

Run continuous local security checks with:

```bash
toolip watch
```

Use `--once` for a non-interactive smoke run.

## Execution behavior

Toolip debounces rapid filesystem changes so a burst of editor writes produces one analysis pass rather than one scan per event.

If a change arrives while analysis is already running, Toolip records a queued rerun and executes it after the current pass completes. This avoids overlapping full scans while still ensuring the latest change is analyzed.

Callback/analyzer failures are reported through the watch error path and do not terminate the watcher. A later filesystem change can therefore recover naturally after a transient provider or analysis failure.

## Ignored paths

Watch mode ignores high-noise/generated paths such as:

- `node_modules`
- `.git`
- `dist`
- `.toolip-report`

Project-specific scan exclusions continue to be handled by Toolip's normal analysis configuration.

## Windows and Node.js 24

Node.js 24 on Windows Server 2025 exposed a native libuv assertion in `fs.watch` when the watched directory is represented by an 8.3 short path but Windows filesystem notifications use the canonical long path.

Toolip v2.2.0 avoids that failure in two ways:

1. Every watch root/directory is canonicalized with `realpathSync.native()` before it is passed to `fs.watch`, so libuv receives the same long-form path representation used by Windows notifications.
2. Windows uses a managed tree of non-recursive directory watchers instead of relying on recursive `fs.watch` for the whole repository. Newly created directories are added as needed.

Debounce, queue, ignore, error-recovery, and close semantics remain unchanged.

macOS/Linux continue to use the platform-supported recursive watcher path after canonical path resolution.

The watcher implementation is covered by cross-platform CI on every supported Node.js release.
