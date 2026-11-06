import { describe, expect, it } from 'vitest';
import { sanitizeOutput } from '../src/core/safe-output.js';

describe('safe output boundaries', () => {
  it('redacts nested values, token URLs, environment assignments and error messages', () => {
    const credential = `ghp_${'a'.repeat(36)}`;
    const result = sanitizeOutput({
      finding: {
        evidence: {
          excerpt: `https://user:${credential}@example.test/?token=${credential}`
        },
        metadata: {
          nested: [{ command: `NPM_TOKEN=${credential}` }],
          password: { current: 'correct horse battery staple' }
        },
        failure: new Error(
          `Authorization: Basic ${Buffer.from('user:pass').toString('base64')}`
        ),
        fingerprint: 'sha256-value'
      }
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(credential);
    expect(serialized).toContain('[redacted]');
    expect(serialized).toContain('[redacted-fingerprint]');
    expect(serialized).not.toContain('sha256-value');
    expect(serialized).not.toContain('correct horse battery staple');
    expect(serialized).not.toContain(
      Buffer.from('user:pass').toString('base64')
    );
  });
});
