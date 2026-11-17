import { describe, expect, it } from 'vitest';
import { renderGitHubPolicyWorkflow } from '../../src/integrations/github/workflow-template.js';

const sha = 'a'.repeat(40);

describe('pinned GitHub Actions policy quickstart', () => {
  it('uses immutable action pins and no privileged PR workflow or secrets', () => {
    const result = renderGitHubPolicyWorkflow({ actionSha: sha });
    expect(result.status).toBe('operator-review-required');
    expect(result.privilegedStageA).toBe(false);
    expect(result.workflow).toContain(`uses: wbizmo/toolip@${sha}`);
    expect(result.workflow).toContain('contents: read');
    expect(result.workflow).not.toContain('on:\n  pull_request_target:');
    expect(result.workflow).not.toContain('secrets.');
    expect(result.workflow).toContain('upload-sarif:');
    expect(result.workflow).toContain('group: toolip-policy-${{ github.ref }}');
  });

  it('requires exact pinned revisions and refuses YAML interpolation through paths', () => {
    for (const actionSha of [
      'main', 'v3', 'abc123', '../refs/heads/main',
      'a'.repeat(39) + '\npermissions: write-all'
    ]) {
      expect(() => renderGitHubPolicyWorkflow({ actionSha })).toThrow();
    }
    expect(() => renderGitHubPolicyWorkflow({
      actionSha: sha,
      policyFile: 'policy.yaml\npermissions: write-all'
    })).toThrow();
    expect(() => renderGitHubPolicyWorkflow({
      actionSha: sha,
      branch: 'main];\n  pull_request_target:'
    })).toThrow();
  });
});
