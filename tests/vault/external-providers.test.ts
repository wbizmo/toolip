import { describe, expect, it, vi } from 'vitest';
import {
  awsSecretsManagerProvider,
  hashicorpVaultProvider,
  onePasswordConnectProvider
} from '../../src/vault/providers/index.js';

const identity = { project: 'project1', environment: 'prod', name: 'service_key' };
const read = { project: 'project1', environments: ['prod'], operations: ['read' as const] };
const write = { project: 'project1', environments: ['prod'], operations: ['write' as const] };

describe('external vault authorization', () => {
  it('rejects cross-project and cross-environment identities before contacting any provider', async () => {
    const fetcher = vi.fn(async () => new Response('{}', { status: 200 }));
    const provider = hashicorpVaultProvider({
      endpoint: 'https://vault.example.test',
      token: 'token',
      mount: 'kv',
      fetcher: fetcher as typeof fetch
    });
    await expect(provider.get(identity, {
      project: 'another', environments: ['prod'], operations: ['read']
    })).rejects.toThrow('Vault access denied');
    await expect(provider.get(identity, {
      project: 'project1', environments: ['staging'], operations: ['read']
    })).rejects.toThrow('Vault access denied');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('reads a scoped HashiCorp KV-v2 value with redirects forbidden', async () => {
    const fetcher = vi.fn(async (_url: string | URL | Request) =>
      new Response(JSON.stringify({ data: { data: { value: 'secret text' } } }), { status: 200 }));
    const provider = hashicorpVaultProvider({
      endpoint: 'https://vault.example.test',
      token: 'token', mount: 'secret',
      fetcher: fetcher as typeof fetch
    });
    expect(await provider.get(identity, read)).toBe('secret text');
    const [url, init] = fetcher.mock.calls[0] as unknown as [URL, RequestInit];
    expect(String(url)).toContain('/v1/secret/data/project1/prod/service_key');
    expect(init.redirect).toBe('error');
  });

  it('never guesses unlisted 1Password items or enumerates vault contents', async () => {
    const fetcher = vi.fn(async () => new Response('{}', { status: 200 }));
    const provider = onePasswordConnectProvider({
      endpoint: 'https://connect.example.test',
      token: 'secret-token',
      vaultId: 'vault-12345',
      itemIds: {},
      fetcher: fetcher as typeof fetch
    });
    await expect(provider.get(identity, read)).rejects.toThrow('not explicitly authorized');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('uses a strict AWS-scoped secret path with injected authenticated client', async () => {
    const client = {
      getSecretValue: vi.fn(async () => ({ SecretString: 'secret-value' })),
      putSecretValue: vi.fn(async () => ({}))
    };
    const provider = awsSecretsManagerProvider(client, 'toolip/secrets');
    expect(await provider.get(identity, read)).toBe('secret-value');
    await provider.set?.(identity, 'next', write);
    expect(client.getSecretValue).toHaveBeenCalledWith({
      SecretId: 'toolip/secrets/project1/prod/service_key',
      abortSignal: undefined
    });
    expect(client.putSecretValue).toHaveBeenCalledWith({
      SecretId: 'toolip/secrets/project1/prod/service_key',
      SecretString: 'next', abortSignal: undefined
    });
  });
});
