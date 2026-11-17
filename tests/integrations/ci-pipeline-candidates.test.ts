import { describe, expect, it } from 'vitest';
import {
  renderEnterpriseSecurityPipeline
} from '../../src/integrations/ci/templates.js';

const image = 'ghcr.io/wbizmo/toolip@sha256:' + 'a'.repeat(64);

describe('Enterprise CI pipeline candidates', () => {
  it('generates an Azure scan with nonprivileged checkout and incomplete-state failure', () => {
    const candidate = renderEnterpriseSecurityPipeline('azure-devops', image);
    expect(candidate.provider).toBe('azure-devops');
    expect(candidate.status).toBe('operator-review-required');
    expect(candidate.releaseApproved).toBe(false);
    expect(candidate.uploadedFindings).toBe(false);
    expect(candidate.yaml).toContain(image);
    expect(candidate.yaml).toContain('persistCredentials: false');
    expect(candidate.yaml).toContain('toolip scan --offline --fail-on-incomplete');
    expect(candidate.yaml).toContain('toolip report azure-annotations');
    expect(candidate.yaml).not.toContain('npm ci');
    expect(candidate.yaml).not.toContain('docker.sock');
  });

  it('generates a Bitbucket scan without untrusted installation hooks', () => {
    const candidate = renderEnterpriseSecurityPipeline('bitbucket', image);
    expect(candidate.provider).toBe('bitbucket');
    expect(candidate.yaml).toContain(image);
    expect(candidate.yaml).toContain('pull-requests:');
    expect(candidate.yaml).toContain('toolip scan --offline --fail-on-incomplete');
    expect(candidate.yaml).toContain('toolip report bitbucket-annotations');
    expect(candidate.yaml).not.toContain('npx');
    expect(candidate.yaml).not.toContain('curl | sh');
  });

  it('refuses mutable images and injected pipeline expressions', () => {
    for (const candidate of [
      'ghcr.io/wbizmo/toolip:latest',
      'ghcr.io/wbizmo/toolip@sha256:' + 'q'.repeat(64),
      image + '\nscript: malicious'
    ]) {
      expect(() => renderEnterpriseSecurityPipeline(
        'azure-devops', candidate
      )).toThrow('exact operator-approved Toolip OCI digest');
      expect(() => renderEnterpriseSecurityPipeline(
        'bitbucket', candidate
      )).toThrow('exact operator-approved Toolip OCI digest');
    }
  });
});
