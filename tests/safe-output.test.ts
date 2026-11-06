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

  it('redacts embedded URL userinfo, quoted CLI values, and errors in secrets', () => {
    const result = sanitizeOutput({
      url: 'https://user:part1@part2@example.test/path?ok=1',
      command: '--password "correct horse battery staple"',
      credentials: new Error('correct horse battery staple'),
      failure: Object.assign(new Error('request failed'), {
        name: `ghp_${'4'.repeat(36)}`
      })
    });
    const serialized = JSON.stringify(result);
    expect(result.command).toBe('--password [redacted]');
    expect(serialized).not.toContain('part1');
    expect(serialized).not.toContain('part2@');
    expect(serialized).not.toContain('correct horse battery staple');
    expect(serialized).not.toContain('ghp_');
    expect(serialized).toContain('https://[redacted]@example.test/path?ok=1');
    expect(
      sanitizeOutput({ url: `https://${'a'.repeat(32)}@example.test` }).url
    ).toBe('https://[redacted]@example.test');
    expect(
      sanitizeOutput({
        url: 'https://example.test/path?next=a@b'
      }).url
    ).toBe('https://example.test/path?next=a@b');
  });

  it('redacts credentials embedded in nested metadata keys', () => {
    const credential = `ghp_${'c'.repeat(36)}`;
    const result = sanitizeOutput({
      metadata: { nested: { [credential]: 'untrusted value' } }
    });

    expect(JSON.stringify(result)).not.toContain(credential);
    expect(result).toEqual({
      metadata: { nested: { '[redacted-token]': 'untrusted value' } }
    });
  });

  it('pseudonymizes fingerprints while preserving secret-specific correlation', () => {
    const first = 'a'.repeat(64);
    const second = 'b'.repeat(64);
    const firstOutput = sanitizeOutput({ fingerprint: first }).fingerprint;
    const repeatedOutput = sanitizeOutput({ fingerprint: first }).fingerprint;
    const secondOutput = sanitizeOutput({ fingerprint: second }).fingerprint;

    expect(firstOutput).toMatch(/^[a-f0-9]{64}$/);
    expect(firstOutput).toBe(repeatedOutput);
    expect(firstOutput).not.toBe(secondOutput);
    expect(firstOutput).not.toBe(first);
  });

  it('redacts unquoted passphrase and passwd assignments in error output', () => {
    const result = sanitizeOutput(
      new Error('unlock failed: passphrase=first-secret passwd=second-secret')
    );
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain('first-secret');
    expect(serialized).not.toContain('second-secret');
    expect(serialized).toContain('passphrase=[redacted]');
    expect(serialized).toContain('passwd=[redacted]');
  });

  it('redacts Bearer and Basic credentials only in Authorization headers', () => {
    const bearer = `Bearer ${'b'.repeat(32)}`;
    const basic = `Basic ${Buffer.from('user:password').toString('base64')}`;
    const result = sanitizeOutput({
      headers: `Authorization: ${bearer}; authorization: ${basic}`,
      curl: `curl -H 'Authorization: ${bearer}'`,
      ordinary: `The words ${bearer} and ${basic} are examples.`
    });

    expect(result.headers).toContain('Bearer [redacted]');
    expect(result.headers).toContain('Basic [redacted]');
    expect(result.curl).toContain('Authorization: Bearer [redacted]');
    expect(result.ordinary).toContain(bearer);
    expect(result.ordinary).toContain(basic);
  });
});
