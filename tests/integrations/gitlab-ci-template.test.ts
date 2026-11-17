import { describe, expect, it } from 'vitest';
import { renderGitlabSecurityPipeline } from '../../src/integrations/gitlab/ci-template.js';

describe('GitLab trusted-image SAST workflow candidate', () => {
  it('uses an exact digest-pinned image without executing project build scripts', () => {
    const image = 'ghcr.io/wbizmo/toolip@sha256:' + 'a'.repeat(64);
    const result = renderGitlabSecurityPipeline(image);
    expect(result.status).toBe('operator-review-required');
    expect(result.stageAApproved).toBe(false);
    expect(result.publishes).toBe(false);
    expect(result.yaml).toContain(image);
    expect(result.yaml).toContain('toolip scan --offline --fail-on-incomplete');
    expect(result.yaml).toContain('toolip report gitlab-sast');
    expect(result.yaml).toContain('sast: gl-sast-report.json');
    expect(result.yaml).not.toContain('npm ci');
    expect(result.yaml).not.toContain('curl | bash');
    expect(result.yaml).not.toContain('docker.sock');
  });

  it('rejects mutable tags, untrusted registries and injected YAML', () => {
    const candidates = [
      'ghcr.io/wbizmo/toolip:latest',
      'ghcr.io/wbizmo/toolip:v3.2.1',
      'evil.example/toolip@sha256:' + 'a'.repeat(64),
      'ghcr.io/wbizmo/toolip@sha256:' + 'x'.repeat(64),
      'ghcr.io/wbizmo/toolip@sha256:' + 'a'.repeat(64) + '\npermissions: write-all'
    ];
    for (const image of candidates)
      expect(() => renderGitlabSecurityPipeline(image)).toThrow(
        'exact trusted Toolip OCI digest'
      );
  });
});
