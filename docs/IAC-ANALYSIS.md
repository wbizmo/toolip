# Infrastructure configuration analysis

Toolip scans Terraform `.tf` files and Kubernetes/GitHub Actions YAML from the
shared immutable project snapshot. Inputs are parsed as data only; templates,
workflow steps, Terraform expressions, and referenced actions are never
executed. Oversized, changed, malformed, or budget-exhausted files contribute
incomplete analyzer coverage rather than a clean result.

The Terraform parser masks quoted strings, line and block comments, and
heredocs before matching resource bodies. Current Terraform checks cover AWS
public S3 ACLs and public-access blocks, public bucket policies, public
administrative/general ingress, and wildcard IAM action/resource pairs. This
is a bounded HCL subset, not a complete Terraform evaluator: variables,
provider aliases, dynamic blocks, and values resolved outside the captured
files are not assumed safe or evaluated. Literal local module sources are
resolved against the shared snapshot so their captured `.tf` files are scanned
with the same rules. Missing or escaping local modules and remote or dynamic
module sources add skipped coverage; Toolip does not download or execute them.

Terraform checks also cover selected Google Cloud and Azure resources: public
Google Cloud Storage IAM members (`allUsers` and `allAuthenticatedUsers`),
Google Compute firewall ingress rules with public source ranges, Azure Storage
accounts that permit public blob access configuration, and Azure Network
Security Rules that allow public inbound traffic. AWS `aws_security_group_rule` and
`aws_vpc_security_group_ingress_rule` ingress resources are checked alongside
`aws_security_group`. Administrative ports and general public ingress retain
separate rule IDs. These are resource-specific HCL patterns; provider aliases,
dynamic expressions, computed CIDRs and policy intent are not evaluated.

Kubernetes YAML is parsed structurally with duplicate-key rejection, bounded
alias traversal, and line-aware findings. Checks bind privileged execution,
host networking, host paths, and non-root security contexts to supported Pod,
Deployment, StatefulSet, DaemonSet, Job, CronJob, and ReplicaSet spec paths.
Each YAML document is isolated. YAML anchors are parsed, but Helm, Kustomize,
Jsonnet, and other template output is not rendered; generated manifests must be
scanned after a trusted render step.

GitHub Actions checks cover write token permissions, mutable repository action
references, mutable `docker://` image references, and common untrusted event
expressions interpolated into `run` scalars. These checks report source
locations and safe rule summaries; shell values and Terraform configuration
values are not copied into evidence. Local composite actions and indirect shell
wrappers require separate review, and the analyzer does not claim a complete
GitHub Actions expression or shell data-flow model.

Dockerfiles are parsed with bounded continuation handling, global build-argument
expansion for `FROM`, and final-stage scoping for root-user and health-check
checks. The effective final `USER` is the last `USER` instruction in the final
stage; a later root switch is not masked by an earlier non-root user. An
unresolved `USER` variable makes Docker coverage partial. The last
`HEALTHCHECK` instruction controls the stage, so `HEALTHCHECK NONE` is reported
even if an earlier check was declared. The health-check finding describes the
Dockerfile instruction state and does not infer metadata inherited from an
external base image. This parser is not a complete Dockerfile frontend.

For a file with `B` source bytes and `N` parsed scalar nodes, scanning is
`O(B + N·D)` time and `O(B + N)` temporary space, where YAML path depth `D` is
capped at 100 and aliases, visits, file size, file count, and aggregate bytes
are bounded by the shared scanner budgets. Terraform block scans use one
comment/string/heredoc masking pass and bounded resource-local matching. Finding
output is deterministically sorted before it is returned.
