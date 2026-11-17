import { describe, expect, it } from 'vitest';
import {
  configuredRemoteVault
} from '../../src/commands/vault-remote.js';

describe('external vault provider configuration trust', () => {
  const identity = {
    project: 'alpha',
    environment: 'production',
    name: 'db-password'
  } as const;

  it('does not use any implicit fallback provider or token when unconfigured', () => {
    expect(() => configuredRemoteVault({
      provider: 'hashicorp-vault', identity, env: {}
    })).toThrow('explicit remote-vault');
    expect(() => configuredRemoteVault({
      provider: '1password-connect', identity, env: {}
    })).toThrow('explicit remote-vault');
  });

  it('configures a scope-restricted HashiCorp provider without passing secrets as CLI arguments', () => {
    const configured = configuredRemoteVault({
      provider: 'hashicorp-vault',
      identity,
      env: {
        TOOLIP_REMOTE_VAULT_ENDPOINT: 'https://vault.example.invalid',
        TOOLIP_REMOTE_VAULT_TOKEN: 'synthetic-test-token',
        TOOLIP_REMOTE_VAULT_MOUNT: 'secret'
      }
    });
    expect(configured.provider.provider).toBe('hashicorp-vault');
    expect(configured.access.project).toBe('alpha');
    expect(configured.access.environments).toEqual(['production']);
    expect(configured.access.operations).toEqual(['read']);
    expect(JSON.stringify(configured.access)).not.toContain('synthetic-test-token');
  });

  it('rejects operator-provided 1Password item IDs outside the bounded explicit identity', () => {
    expect(() => configuredRemoteVault({
      provider: '1password-connect',
      identity,
      env: {
        TOOLIP_REMOTE_VAULT_ENDPOINT: 'https://op.example.invalid',
        TOOLIP_REMOTE_VAULT_TOKEN: 'synthetic-test-token',
        TOOLIP_REMOTE_VAULT_ID: 'vault-12345',
        TOOLIP_REMOTE_ITEM_ID: '../../foreign/item'
      }
    })).toThrow('explicit remote-vault');
  });

  it('refuses an unrecognized provider rather than silently returning local secrets', () => {
    expect(() => configuredRemoteVault({
      provider: 'aws-secrets-manager-unconfigured',
      identity,
      env: {
        TOOLIP_REMOTE_VAULT_ENDPOINT: 'https://vault.example.invalid',
        TOOLIP_REMOTE_VAULT_TOKEN: 'synthetic-token'
      }
    })).toThrow('explicit remote-vault');
  });
});
