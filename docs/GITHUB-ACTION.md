# GitHub Action

The composite action in `action.yml` runs `toolip policy check`, writes a
redacted SARIF 2.1.0 file, and returns the policy command's exit status. It
installs the action revision's locked dependencies with lifecycle scripts
disabled, verifies registry signatures, and then builds that pinned Toolip
revision. It does not install or execute scripts from the scanned repository.

SARIF upload is available as an explicit opt-in with `upload-sarif: 'true'`.
The composite action uses a pinned CodeQL uploader and skips uploads for fork
pull requests, including `pull_request_target`. It also skips `workflow_run`
events because their associated pull request context may be incomplete. The
calling job must grant `security-events: write`; the action cannot grant
permissions itself. Use the separate upload-job example below when the
workflow should keep that permission off the scanning job.

Pin the action to a reviewed immutable commit SHA. Keep the workflow token
read-only for scanning, and grant `security-events: write` only to a separate
SARIF upload step when the event and repository permissions allow it. Fork PRs
must not receive publishing, deployment, or other write-scoped secrets. The
SARIF upload action should also be pinned to an immutable SHA.

```yaml
permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<reviewed-immutable-sha>
        with:
          persist-credentials: false
      - uses: wbizmo/toolip@<reviewed-immutable-sha>
        with:
          repository-path: .
          policy-file: .toolip/policy.yaml
          fail-on: high
          offline: 'true'
          timeout-ms: '120000'
          sarif-output: toolip.sarif
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: toolip-sarif
          path: toolip.sarif
          if-no-files-found: error

  upload:
    needs: scan
    if: github.event_name != 'workflow_run' && (!github.event.pull_request || github.event.pull_request.head.repo.fork == false)
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          name: toolip-sarif
      - uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        if: github.event_name != 'workflow_run' && (!github.event.pull_request || github.event.pull_request.head.repo.fork == false)
        with:
          sarif_file: toolip.sarif
```

Pin Toolip to a reviewed immutable commit SHA. The scan job has read
permissions only; the separate upload job receives `security-events: write`
only for events that are not fork pull requests and are not `workflow_run`.
The artifact actions and GitHub Code Scanning uploader are also pinned to
immutable SHAs. Fork scans never receive a write-scoped token.

For a trust boundary that must run before `npm ci`, builds, or repository-owned
commands, use Toolip's separate Stage A workflow. This action is a policy and
SARIF integration for an already-running workflow; it is not a replacement for
Stage A. GitHub repository rulesets, required checks, independent reviews,
CODEOWNERS, signed-commit requirements, and restricted push rights remain
server-side settings that maintainers must configure and verify.
