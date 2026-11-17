/**
 * GitLab CI candidate for a separately approved, immutable Toolip OCI image.
 * This template performs read-only project inspection and requires an
 * administrator-selected trusted image digest. It must not be marketed as
 * an approved Stage A gate or as a replacement for GitLab branch protection.
 */
export type GitlabPipelineCandidate = Readonly<{
  schema: 'toolip.dev/gitlab-ci-template/v1';
  status: 'operator-review-required';
  stageAApproved: false;
  publishes: false;
  yaml: string;
}>;

const imagePattern =
  /^ghcr\.io\/wbizmo\/toolip@sha256:[a-f0-9]{64}$/u;

export function renderGitlabSecurityPipeline(
  trustedImage: string
): GitlabPipelineCandidate {
  if (!imagePattern.test(trustedImage))
    throw new TypeError(
      'GitLab candidate requires an exact trusted Toolip OCI digest. Tags and image aliases are rejected.'
    );
  const yaml = `# REVIEW CANDIDATE ONLY. Requires an independently approved Toolip
# image, administrator-owned protected-branch controls and isolated runners.
# Project-controlled install/build scripts are intentionally never executed.
# No secrets, release credentials, Docker socket or elevated privileges.
stages:
  - security

toolip_security:
  stage: security
  image:
    name: "${trustedImage}"
    entrypoint: [""]
  variables:
    TOOLIP_NO_TELEMETRY: "1"
  script:
    - "toolip scan --offline --fail-on-incomplete --output toolip.json"
    - "toolip report gitlab-sast toolip.json --output gl-sast-report.json"
  artifacts:
    when: always
    expire_in: 1 day
    paths:
      - toolip.json
      - gl-sast-report.json
    reports:
      sast: gl-sast-report.json
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
`;
  return Object.freeze({
    schema: 'toolip.dev/gitlab-ci-template/v1',
    status: 'operator-review-required',
    stageAApproved: false,
    publishes: false,
    yaml
  });
}
