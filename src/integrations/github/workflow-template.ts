/**
 * Non-privileged, digest-pinned CI quickstart. It invokes the pre-existing
 * Toolip action and DOES NOT replace the independently administered Stage A
 * protected-base bootstrap required for privileged release gating.
 */
const commitPattern = /^[a-f0-9]{40}$/u;
const branchPattern = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u;
const policyPattern = /^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.(?:yml|yaml|json)$/u;
const checkoutSha = '3d3c42e5aac5ba805825da76410c181273ba90b1';

export type GitHubWorkflowTemplate = Readonly<{
  schema: 'toolip.dev/github-ci-template/v1';
  status: 'operator-review-required';
  privilegedStageA: false;
  workflow: string;
}>;

export function renderGitHubPolicyWorkflow(input: {
  actionSha: string;
  branch?: string;
  policyFile?: string;
}): GitHubWorkflowTemplate {
  const branch = input.branch ?? 'main';
  const policyFile = input.policyFile ?? '.toolip/policy.yaml';
  if (
    !commitPattern.test(input.actionSha) ||
    !branchPattern.test(branch) ||
    branch === '..' || branch.includes('../') ||
    !policyPattern.test(policyFile) ||
    policyFile.split('/').some((part) => part === '..' || part === '.')
  )
    throw new TypeError(
      'Quickstart requires an operator-selected immutable action commit, safe branch and policy file.'
    );
  const workflow = `# Non-privileged Toolip policy check only.
# Operator must validate action revision, install a real versioned policy file,
# and configure independently trusted Stage A before relying on release gates.
# This workflow must never use pull_request_target or untrusted PR secrets.
name: Toolip policy check

on:
  push:
    branches: [${branch}]
  pull_request:

permissions:
  contents: read

concurrency:
  group: toolip-policy-\${{ github.ref }}
  cancel-in-progress: true

jobs:
  toolip:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Checkout source for read-only inspection
        uses: actions/checkout@${checkoutSha}
        with:
          persist-credentials: false
      - name: Run pinned Toolip policy evaluation
        uses: wbizmo/toolip@${input.actionSha}
        with:
          repository-path: .
          policy-file: ${policyFile}
          offline: 'true'
          fail-on: high
          upload-sarif: 'false'
`;
  return Object.freeze({
    schema: 'toolip.dev/github-ci-template/v1',
    status: 'operator-review-required',
    privilegedStageA: false,
    workflow
  });
}
