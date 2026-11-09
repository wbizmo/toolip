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

Repository policy is always untrusted. An organization policy can authorize
privileged overrides and suppressions only as a signed JSON envelope with
schema `toolip.dev/organization-policy/v1`. The envelope contains `issuer`,
`keyId`, canonical UTC `issuedAt` and `expiresAt`, a normal version 1 `policy`,
and an Ed25519 `signature` over canonical JSON of every envelope field except
`signature`. Validity is limited to 180 days. The public key, expected key ID,
and expected issuer must come from operator-controlled configuration outside
the scanned repository:

```sh
toolip policy check \
  --organization-policy /etc/toolip/org-policy.json \
  --organization-policy-public-key /etc/toolip/org-policy.pub \
  --organization-policy-key-id org-policy-v3 \
  --organization-policy-issuer security.example/toolip \
  --require-organization-policy
```

Unsigned policies, an unexpected signer or issuer, malformed or expired
envelopes, and missing trust inputs are `misconfigured`; the CLI does not fall
back to repository policy when an organization policy was explicitly supplied.
`--require-organization-policy` also fails when its path was omitted. MCP takes
the same trust values only through server startup configuration, never from
tool arguments or repository files. A signature binds the policy content,
signer, issuer, and validity interval; each privileged suppression is therefore
bound to that signed policy identity as well as its rule ID, optional path,
rationale, and expiry. Untrusted organization overlays can make thresholds
stricter but cannot grant suppressions, lower severity, or weaken coverage.

`policy check` uses the shared security scorecard findings, including
vulnerability analysis and aggregate completion state. Add `--offline` to
prohibit provider requests; missing or stale advisory data leaves the decision
incomplete. `blockKnownExploited: true` fails the gate for CISA KEV findings
independently of their CVSS severity, even if a trusted layer tries to disable
or suppress that finding. The policy source SHA-256 and decision provenance are
included in command output and SARIF policy metadata. A signed organization
profile can be passed to the composite action with `organization-policy-file`,
`organization-policy-public-key`, `organization-policy-key-id`,
`organization-policy-issuer`, and `require-organization-policy`. The workflow
must source all five values from protected organization configuration and must
not permit a pull request to redefine its trust root. The GitHub Action runs
this same policy command and returns its exit status. MCP's
`toolip_policy_check` can evaluate the same signed organization layer when it
is configured at server startup. Public metadata providers do not receive scoped npm package names
or packages resolved from custom registries by default. The
`--allow-public-scope` flag is explicit consent to share scoped names for public
package metadata and advisory lookups; use it only when those names are public.

This is the first policy version. Central profile distribution, key rotation
and revocation services, and persistent approval audit records are not
implemented. Do not use repository policy as authority for privileged
suppressions or source organization trust roots from repository-controlled
workflow arguments.
