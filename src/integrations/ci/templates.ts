/** CI recipe candidates share the same immutable, separately approved
 * Toolip OCI runtime. They do not install a scanner, run a project build,
 * grant credentials, upload annotations or establish enterprise approval.
 */
const approvedImagePattern =
  /^ghcr\.io\/wbizmo\/toolip@sha256:[a-f0-9]{64}$/u;
export type PipelineCandidate = Readonly<{
  schema: 'toolip.dev/ci-pipeline-candidate/v1';
  provider: 'azure-devops' | 'bitbucket';
  status: 'operator-review-required';
  releaseApproved: false;
  uploadedFindings: false;
  image: string;
  yaml: string;
}>;

export function renderEnterpriseSecurityPipeline(
  provider: 'azure-devops' | 'bitbucket',
  image: string
): PipelineCandidate {
  if (!approvedImagePattern.test(image))
    throw new TypeError(
      'CI candidate requires an exact operator-approved Toolip OCI digest.'
    );
  const warning =
    '# CANDIDATE ONLY. Verify this image and the platform runner separately.\n' +
    '# No untrusted install/build scripts, privileged tokens or publication.\n';
  const yaml = provider === 'azure-devops'
    ? `${warning}trigger:
  branches:
    include: [main]
pr:
  branches:
    include: [main]
resources:
  containers:
    - container: toolip
      image: "${image}"
jobs:
  - job: toolip_security
    timeoutInMinutes: 20
    pool:
      vmImage: ubuntu-24.04
    container: toolip
    steps:
      - checkout: self
        persistCredentials: false
      - script: toolip scan --offline --fail-on-incomplete --output toolip.json
        displayName: Offline Toolip scan
      - script: toolip report azure-annotations toolip.json
        displayName: Emit escaped Azure annotations
        condition: succeededOrFailed()
      - publish: toolip.json
        artifact: toolip-report
        condition: succeededOrFailed()
`
    : `${warning}image: "${image}"
pipelines:
  pull-requests:
    '**':
      - step:
          name: Offline Toolip security
          script:
            - toolip scan --offline --fail-on-incomplete --output toolip.json
            - toolip report bitbucket-annotations toolip.json --output bitbucket-annotations.json
          artifacts:
            - toolip.json
            - bitbucket-annotations.json
  branches:
    main:
      - step:
          name: Offline Toolip security
          script:
            - toolip scan --offline --fail-on-incomplete --output toolip.json
            - toolip report bitbucket-annotations toolip.json --output bitbucket-annotations.json
          artifacts:
            - toolip.json
            - bitbucket-annotations.json
`;
  return Object.freeze({
    schema: 'toolip.dev/ci-pipeline-candidate/v1',
    provider,
    status: 'operator-review-required',
    releaseApproved: false,
    uploadedFindings: false,
    image,
    yaml
  });
}
