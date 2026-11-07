# Policy as code (experimental)

Toolip accepts a version 1 JSON or YAML policy at `.toolip/policy.yaml`. The
parser rejects duplicate YAML keys, unknown fields, unsupported versions,
invalid severity names, unsafe suppression paths, more than 5,000 per-rule
overrides, or more than 1,000 suppressions. Suppression globs are compiled once
and indexed by rule ID before evaluating findings. A policy file is
data: Toolip never evaluates expressions or executes its contents.

Run `toolip policy check` to scan the current project and emit a machine-readable
decision. `toolip policy explain` emits the same decision with all findings,
including findings below the configured threshold. Both commands are
read-only. They report `pass`, `fail`, `incomplete`, or `misconfigured`; the
exit codes are 0, 2, 3, and 1 respectively. An incomplete scorecard scan
cannot produce `pass`.

Supported fields include severity and coverage thresholds, known-exploited
blocking, named rule sets, per-rule overrides, and expiring suppressions:

```yaml
version: 1
minimumSeverity: high
minimumCoverage: 0.95
blockKnownExploited: true
ruleSets:
  - all
rules:
  TLP-EXAMPLE-001:
    enabled: true
    severity: critical
suppressions:
  - id: reviewed-example
    ruleId: TLP-EXAMPLE-001
    path: src/legacy/**
    expiresAt: 2030-01-01T00:00:00.000Z
    reason: Reviewed exception for the migration window
```

Severity values are `critical`, `high`, `medium`, `low`, and `info`. The
default failure threshold is `high`. Rule-set names are `all`,
`application-security`, `infrastructure`, `secrets`, `supply-chain`, and
`git-security`. Coverage is a ratio from 0 through 1; absent or insufficient
coverage cannot pass. Untrusted repository policy cannot disable a rule, lower
its severity, or authorize its own suppressions. Expired suppressions make the
policy misconfigured, even if no finding matches them.

Repository policy is always untrusted. A local operator may provide an
independently managed policy with
`--organization-policy <file> --trust-organization-policy`; the flag is an
explicit local approval and does not verify a signature. CI must source the
policy path and approval from protected workflow configuration, never from the
repository being scanned. Untrusted organization overlays can make thresholds
stricter but cannot grant suppressions, lower severity, or weaken coverage.

`policy check` uses the shared security scorecard findings, including
vulnerability analysis and aggregate completion state. Add `--offline` to
prohibit provider requests; missing or stale advisory data leaves the decision
incomplete. `blockKnownExploited: true` fails the gate for CISA KEV findings
independently of their CVSS severity, even if a trusted layer tries to disable
or suppress that finding. The policy source SHA-256 and decision provenance are
included in command output and SARIF policy metadata. The GitHub Action runs
this same policy command and returns its exit status. MCP's
`toolip_policy_check` evaluates repository policy as untrusted data and returns
the same fail-closed decision class; it does not accept privileged organization
suppressions. Public metadata providers do not receive scoped npm package names
or packages resolved from custom registries by default. The
`--allow-public-scope` flag is explicit consent to share scoped names for public
package metadata and advisory lookups; use it only when those names are public.

This is the first policy version. Organization signature verification,
centrally distributed compliance profiles, policy inheritance, and persistent
approval audit records are not implemented. Do not use repository policy as
authority for privileged suppressions.
