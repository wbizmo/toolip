import { generateKeyPairSync, verify as verifySignature } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { GitHubAppApiClient } from '../../src/core/github/app-api.js';
import type {
  GitHubAppRepository,
  GitHubAppScanSummary,
  GitHubAppScanWork
} from '../../src/core/github/app-webhook.js';

const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKey = keyPair.privateKey
  .export({ type: 'pkcs8', format: 'pem' })
  .toString();
const publicKey = keyPair.publicKey;
const now = Date.parse('2026-11-07T00:00:00.000Z');
const installationToken = ['ghs_', 'test_installation_token_value'].join('');
const repository: GitHubAppRepository = {
  name: 'acme/service',
  installationId: 42,
  repositoryId: 123,
  root: '/srv/acme-service'
};
const work: GitHubAppScanWork = {
  kind: 'push',
  installationId: 42,
  repository: 'acme/service',
  repositoryId: 123,
  revision: 'a'.repeat(40),
  deliveryId: 'delivery-1'
};

function response(value: unknown, status: number): Response {
  return new Response(JSON.stringify(value), { status });
}

describe('least-privilege GitHub App check-run API', () => {
  it('signs a short-lived App JWT, scopes one-repository checks token, and uploads only a redacted result', async () => {
    const requests: Array<{ url: string; init: RequestInit }> = [];
    let tokenRequests = 0;
    const client = new GitHubAppApiClient({
      appId: '12345',
      privateKey,
      now: () => now,
      fetchImplementation: async (input, init = {}) => {
        const url = String(input);
        requests.push({ url, init });
        if (url.endsWith('/app/installations/42/access_tokens')) {
          tokenRequests++;
          return response(
            {
              token: installationToken,
              expires_at: '2026-11-07T01:00:00.000Z',
              repository_selection: 'selected',
              repositories: [{ id: 123 }],
              permissions: { checks: 'write', metadata: 'read' }
            },
            201
          );
        }
        return response({ id: 456 }, 201);
      }
    });

    const complete: GitHubAppScanSummary = {
      status: 'complete',
      findingCount: 0,
      revision: 'a'.repeat(40),
      snapshotId: 'b'.repeat(64)
    };
    await client.createSecurityCheck(work, repository, complete);
    await client.createSecurityCheck(
      { ...work, deliveryId: 'delivery-2' },
      repository,
      {
        ...complete,
        findingCount: 2,
        annotations: [
          {
            path: 'src/a.ts',
            line: 12,
            severity: 'high',
            ruleId: 'TLP-TEST-001'
          },
          {
            path: '../../etc/passwd',
            line: 1,
            severity: 'critical',
            ruleId: 'TLP-TEST-002'
          }
        ]
      }
    );
    await client.createSecurityCheck(
      { ...work, deliveryId: 'delivery-3' },
      repository,
      { ...complete, status: 'incomplete' }
    );

    expect(tokenRequests).toBe(1);
    const tokenRequest = requests[0];
    expect(tokenRequest?.url).toBe(
      'https://api.github.com/app/installations/42/access_tokens'
    );
    expect(JSON.parse(String(tokenRequest?.init.body))).toEqual({
      repository_ids: [123],
      permissions: { checks: 'write' }
    });
    const jwt = new Headers(tokenRequest?.init.headers)
      .get('authorization')
      ?.slice('Bearer '.length);
    expect(jwt).toBeDefined();
    const [header, payload, signature] = (jwt ?? '').split('.');
    expect(
      JSON.parse(Buffer.from(header ?? '', 'base64url').toString())
    ).toEqual({
      alg: 'RS256',
      typ: 'JWT'
    });
    expect(
      JSON.parse(Buffer.from(payload ?? '', 'base64url').toString())
    ).toMatchObject({
      iss: '12345',
      iat: Math.floor(now / 1_000) - 30,
      exp: Math.floor(now / 1_000) + 8 * 60
    });
    expect(
      verifySignature(
        'RSA-SHA256',
        Buffer.from(`${header}.${payload}`),
        publicKey,
        Buffer.from(signature ?? '', 'base64url')
      )
    ).toBe(true);

    const checks = requests.filter((request) =>
      request.url.endsWith('/check-runs')
    );
    expect(checks).toHaveLength(3);
    const checkBodies = checks.map(
      (request) =>
        JSON.parse(String(request.init.body)) as Record<string, unknown>
    );
    expect(checkBodies.map((body) => body.conclusion)).toEqual([
      'success',
      'failure',
      'failure'
    ]);
    expect(checkBodies[0]).toMatchObject({
      name: 'Toolip Security',
      head_sha: 'a'.repeat(40),
      status: 'completed',
      output: { title: 'Toolip scan completed with no findings' }
    });
    const annotatedOutput = checkBodies[1]?.output as Record<string, unknown>;
    expect(annotatedOutput?.annotations).toEqual([
      {
        path: 'src/a.ts',
        start_line: 12,
        end_line: 12,
        annotation_level: 'failure',
        message: expect.stringContaining('TLP-TEST-001')
      }
    ]);
    expect(JSON.stringify(checkBodies)).not.toContain('/srv/acme-service');
    expect(JSON.stringify(checkBodies)).not.toContain('/src/');
    expect(checkBodies).not.toContainEqual(
      expect.objectContaining({ source: expect.anything() })
    );
    expect(
      checks.every(
        (request) =>
          new Headers(request.init.headers).get('authorization') ===
          `Bearer ${installationToken}`
      )
    ).toBe(true);
  });

  it('fails closed for malformed scan identity and failed GitHub API responses', async () => {
    const client = new GitHubAppApiClient({
      appId: '12345',
      privateKey,
      now: () => now,
      fetchImplementation: async () => response({ message: 'unavailable' }, 403)
    });
    await expect(
      client.createSecurityCheck(work, repository, {
        status: 'complete',
        findingCount: 0,
        revision: 'invalid'
      })
    ).rejects.toThrow('github-check-revision-unavailable');
    await expect(
      client.createSecurityCheck(work, repository, {
        status: 'incomplete',
        findingCount: 0,
        revision: 'a'.repeat(40)
      })
    ).rejects.toThrow('github-installation-token-request-failed');
    expect(() => new GitHubAppApiClient({ appId: '0', privateKey })).toThrow(
      'App ID is invalid'
    );
  });

  it('rejects RSA private keys below the 2048-bit minimum', () => {
    const weakKey = generateKeyPairSync('rsa', { modulusLength: 1024 })
      .privateKey.export({ type: 'pkcs8', format: 'pem' })
      .toString();
    expect(
      () => new GitHubAppApiClient({ appId: '12345', privateKey: weakKey })
    ).toThrow('at least 2048 bits');
  });

  it('rejects dot-segment repository names before requesting an installation token', async () => {
    let requests = 0;
    const client = new GitHubAppApiClient({
      appId: '12345',
      privateKey,
      now: () => now,
      fetchImplementation: async () => {
        requests += 1;
        return response({}, 201);
      }
    });
    const unsafeRepository = { ...repository, name: 'acme/..' };
    await expect(
      client.createSecurityCheck(
        { ...work, repository: unsafeRepository.name },
        unsafeRepository,
        { status: 'incomplete', findingCount: 0, revision: work.revision }
      )
    ).rejects.toThrow('github-check-identity-mismatch');
    expect(requests).toBe(0);
  });

  it('keeps cancellation and timeout active while reading an API response body', async () => {
    const client = new GitHubAppApiClient({
      appId: '12345',
      privateKey,
      now: () => now,
      fetchImplementation: async (_input, init = {}) => {
        let streamController:
          ReadableStreamDefaultController<Uint8Array> | undefined;
        const stream = new ReadableStream<Uint8Array>({
          start(value) {
            streamController = value;
          }
        });
        init.signal?.addEventListener(
          'abort',
          () => streamController?.error(new Error('aborted')),
          { once: true }
        );
        return new Response(stream, { status: 201 });
      }
    });
    const abort = new AbortController();
    const pending = client.createSecurityCheck(
      work,
      repository,
      { status: 'complete', findingCount: 0, revision: work.revision },
      abort.signal
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    abort.abort();
    await expect(pending).rejects.toThrow('github-api-request-aborted');
  });

  it('cancels rejected API response bodies instead of retaining them', async () => {
    let cancelled = false;
    const client = new GitHubAppApiClient({
      appId: '12345',
      privateKey,
      now: () => now,
      fetchImplementation: async () => {
        const body = new ReadableStream<Uint8Array>({
          cancel() {
            cancelled = true;
          }
        });
        return new Response(body, { status: 403 });
      }
    });
    await expect(
      client.createSecurityCheck(work, repository, {
        status: 'incomplete',
        findingCount: 0,
        revision: work.revision
      })
    ).rejects.toThrow('github-installation-token-request-failed');
    expect(cancelled).toBe(true);
  });

  it('rejects an installation token response broader than the requested scope', async () => {
    const client = new GitHubAppApiClient({
      appId: '12345',
      privateKey,
      now: () => now,
      fetchImplementation: async () =>
        response(
          {
            token: installationToken,
            expires_at: '2026-11-07T01:00:00.000Z',
            repository_selection: 'selected',
            repositories: [{ id: 123 }, { id: 456 }],
            permissions: { checks: 'write', contents: 'read' }
          },
          201
        )
    });
    await expect(
      client.createSecurityCheck(work, repository, {
        status: 'incomplete',
        findingCount: 0,
        revision: work.revision
      })
    ).rejects.toThrow('github-installation-token-response-invalid');
  });
});
