# Read-only GitHub App webhook runner

Toolip can run opt-in, read-only scans for an installation-scoped repository
allowlist. The runner accepts GitHub-signed `push` and `repository_dispatch`
webhooks, rejects replayed delivery IDs, processes installation suspension
events, and bounds request bodies, queued scans, concurrent scans and scan
deadlines. It reuses the normal Toolip scorecard and emits redacted status
summaries to stderr.

The host must provision each exact commit into a local checkout before a push
scan is accepted as complete. Toolip verifies that `HEAD` matches the webhook
revision and that the worktree and index are clean both before and after
snapshot capture, then checks again after scorecard analysis. It then compares
the captured file set and SHA-256 content
digests with regular blobs from the exact commit tree. This rejects an edit
that is restored before the second status check, as well as link/submodule or
over-budget trees whose contents cannot be proven. A binary executable blob is
incomplete because its content is not analyzed. Git LFS pointer files are also
incomplete because the referenced payload is not provisioned. A mismatch or
unavailable Git object makes the summary incomplete and no check is reported as
a pass. The post-analysis snapshot revalidation also rejects persistent changes
observed while the Git audit or other scorecard tasks ran.
The scan operates on the captured snapshot after these identity checks. It does
not clone, check out, install, build, comment on, or write to repositories.
Scheduled scans use the current clean local `HEAD`. Offline advisory mode is
the default; `--online` opts into public advisory providers, while scoped
package names remain withheld.

Create a private local configuration file outside the scanned repositories:

```json
{
  "version": 1,
  "repositories": [
    {
      "name": "acme/service",
      "installationId": 123456,
      "repositoryId": 987654321,
      "root": "/srv/checkouts/acme-service"
    }
  ]
}
```

Set a random GitHub App webhook secret with at least 32 bytes and start the
service behind a TLS-terminating reverse proxy:

```sh
export TOOLIP_GITHUB_APP_WEBHOOK_SECRET='...'
export TOOLIP_GITHUB_APP_ID='123456'
export TOOLIP_GITHUB_APP_PRIVATE_KEY='...'
toolip github-app serve --config /etc/toolip/github-app.json --host 127.0.0.1 --port 8787 --schedule-hours 24
```

Configure the GitHub App with only **Checks: read and write**, subscribe to
`push`, `installation`, and `repository_dispatch`, set the webhook URL to
`/webhook`, and install it only on repositories in the local allowlist. The
service requests a short-lived installation token scoped to one configured
repository ID and `checks: write`. The webhook secret authenticates GitHub
delivery; repository names, repository IDs and installation IDs are checked
against the local allowlist. Check runs contain scan state, finding count, and
at most 50 redacted annotations with a relative file path, line, severity, and
rule ID. Source excerpts and arbitrary finding messages are never uploaded.
Malformed, absolute, parent-traversal, or credential-bearing paths are omitted.
Repeated scheduled requests for a repository are coalesced while its scheduled
scan is queued or active; scheduling can run again after that scan settles.
Do not expose
the HTTP listener directly to the public Internet without a TLS-terminating
reverse proxy and network-level rate limits.

The runner stores hashed delivery IDs, their expiry times, and suspended
installation IDs in a private local journal (default:
`~/.toolip-github-app-state/deliveries.json`). Writes are atomic and protected
by a cross-process lock. The journal is bounded and reloaded at startup; a
state read/write or retention-budget failure returns HTTP 503 and leaves the
delivery unacknowledged for GitHub retry. `--state-file` can place this file on
an administrator-managed private filesystem.

The runner creates a GitHub check run for the exact scanned commit and fails it
when findings exist or scan coverage is incomplete. The scan callback must
return the exact revision it scanned; a missing or different revision is
rejected before requesting an installation token or creating a check. It does not upload SARIF,
post PR comments, or create pull requests, and it does not provision remote
commits. Use the separate GitHub Action workflow for SARIF upload. The host
must provision remote commits before the scan request is accepted; this service
never fetches untrusted repository content itself.

The webhook hot path is bounded by request bytes `B ≤ 1 MiB`, cached delivery
IDs `D ≤ 10,000` in memory and at most 100,000 persisted IDs by default, queued
scans `Q ≤ 64`, and active scans `C ≤ 2`. The journal is capped at 16 MiB.
Exact local-scan identity validation performs HEAD and status checks before and
after snapshot capture and after scorecard analysis, `O(F)` status work for
`F` working-tree entries, with each status response capped at 1 MiB. Final
snapshot revalidation adds `O(F+B)` time and `O(F)` path-index space for `B`
captured bytes; file bytes are hashed one at a time with a 2 MiB per-file cap.
Exact commit comparison parses at most
20,000 tree files/16 MiB of tree metadata, then hashes at most 64 MiB of unique
regular Git blobs; its time is `O(F + B_g)` and temporary space is `O(F + B_g)`
for `B_g ≤ 64 MiB`. Snapshot content remains resident during comparison. The
status checks catch ordinary persistent updates while blob comparison catches
transient edits restored before the final check. Signature validation and JSON
parsing are `O(B)` time and `O(B)` temporary space; delivery lookup is expected
`O(1)` in memory and `O(D)` to parse the bounded persistent snapshot. Peak
additional service memory is `O(B + D + Q + C·(S + B_g))`, where `S` is each
active scorecard's configured bounded scan memory. Increasing queue,
concurrency, body, journal or file budgets increases resource use linearly and
is restricted by constructor limits. The scheduled-scan coalescing set is
`O(R)` for at most 100 allowlisted repositories.
