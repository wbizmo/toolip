# Git Security Behavior

How Toolip's Git-facing features decide what to scan, where hooks go, and what "ignored" means. These guarantees apply to the unreleased v3.2.1 work (Batch 02); the published v2.2.1 behaves as described in its own release notes.

## Pre-commit scans what will be committed

`toolip pre-commit` (and the hook that runs it) scans the **staged blobs** read from Git's object database, not the working-tree files.

- Staged paths come from `git diff --cached --raw -z` (NUL-delimited, so spaces, newlines and non-ASCII names are safe). Renames are handled as delete + add, so the new path is scanned.
- Content comes from one `git cat-file --batch` process keyed by object ID. The worktree is never opened, so partial staging, a clean worktree next to a dirty index, files deleted from the worktree after staging, and `git commit <paths>` (which uses a temporary index via `GIT_INDEX_FILE`) all scan the correct bytes.
- An unstaged-only secret does not block a safe commit; a staged secret blocks it even if the working copy was cleaned.
- `--full` is an explicit worktree-wide manual check and is labelled `scope: full`.

**Fail-closed behavior.** The command exits non-zero and does not report "passed" when Git cannot be run, the index listing cannot be parsed, a staged object cannot be read, or the index has unmerged entries (`PRE_COMMIT_UNMERGED_PATHS`).

**Not content-scanned (listed as warnings, not silently passed):** binary blobs, blobs over the per-file budget, symbolic links, and submodules (gitlinks). Treating oversized or binary content as incomplete coverage is tightened further by the analyzer-completion work in Batch 03.

Limits: staged blobs are bounded by the text-file budget (2 MiB per file, 64 MiB total, 20,000 files by default). Complexity is O(S + B) for S staged paths and B scanned bytes.

## Hook installation

`toolip hook install` resolves Git's **effective** hooks directory instead of assuming `.git/hooks`:

1. `core.hooksPath` if set (relative values resolve against the work-tree top level), else
2. `git rev-parse --git-path hooks` (which is the shared hooks directory when run from a linked worktree).

Husky v9's generated `.husky/_` directory is redirected to `.husky/pre-commit`, and a warning is printed when the hook or directory looks managed by Husky, Lefthook or simple-git-hooks (regeneration can remove the block; prefer adding `toolip pre-commit --path .` to that tool's configuration).

The managed block is idempotent (exactly one, byte-identical on re-run) and is placed **immediately after the shebang**, so an `exit` or `exec` in existing logic cannot silently bypass it. Re-running migrates blocks that older versions appended after an `exit`. Existing content is preserved, the file is replaced atomically, and non-shell hooks (for example Python or Node) are refused rather than rewritten. A corrupt or duplicated block is an error and the file is left untouched.

The hook never downloads anything. It uses the project-local `node_modules/.bin/toolip` (pinned by your lockfile), else a `toolip` on `PATH`, else exits 1 with install instructions.

## Ignore and tracked-file audit

`toolip git-audit` asks Git instead of reading `.gitignore` text:

- Ignore status comes from `git check-ignore --no-index -v` on representative paths (`.env`, `.env.local`, `.env.production`, `server.pem`, `private.key`) and on sensitive files actually present, so precedence, negation (`!.env`), comments, lookalike patterns and nested `.gitignore` files behave exactly as in Git.
- **Tracked** sensitive files (`.env`, PEM, keys) are found with `git ls-files -z` and reported separately, because ignore rules do not protect files already in the index. Template files such as `.env.example`, `.env.sample` and `.env.template` are allowed.
- Policy presence (a `.gitignore` exists), observed ignore status and tracked exposure are reported as separate facts, and findings carry an `Observed with git …` evidence line to separate them from heuristic advice.
- Outside a Git work tree the status is **unknown**: Toolip emits `TOOLIP-GIT-STATUS-UNKNOWN` and does not guess that anything is protected or unprotected.

## Git revisions (`toolip diff`, MCP `toolip_diff`)

Revisions are validated, then resolved to commit object IDs with `git rev-parse --verify --end-of-options`, and only those hexadecimal IDs are passed to `git diff` (with external diff, textconv and renames disabled, bounded output and time). Accepted: branch and tag names, `HEAD` and commit IDs. Rejected: anything starting with `-`, ranges (`a..b`, `a...b`), revision expressions (`HEAD~1`, `HEAD^`, `x:path`, `@{u}`), whitespace, control characters and over-long values. Use a commit ID instead of `HEAD~1`.

Before this change the range was one string, `${base}..${head}`, so a value such as `--output=/path` was parsed by Git as an option and created a file. Invalid or unknown revisions now return a typed error (`GIT_REVISION_INVALID`, `GIT_REVISION_NOT_FOUND`); over MCP these are structured `isError` results that contain no filesystem paths.

Requires Git 2.24 or newer (`--end-of-options`); older Git fails closed.
