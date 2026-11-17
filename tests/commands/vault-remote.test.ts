import { describe, expect, it, vi } from 'vitest';
import { createProgram } from '../../src/cli/program.js';

const args = [
  'node', 'toolip', 'vault', 'remote', 'get', 'db-password',
  '--provider', 'hashicorp-vault',
  '--project', 'alpha',
  '--env', 'production'
];

describe('remote vault CLI consent boundaries', () => {
  it('refuses to call any provider until network consent is explicitly provided', async () => {
    await expect(createProgram().parseAsync(args)).rejects.toThrow(
      'requires explicit --enable-network'
    );
  });

  it('never falls back to the local encrypted vault when the remote config is unavailable', async () => {
    const before = process.env.TOOLIP_REMOTE_VAULT_TOKEN;
    const priorEndpoint = process.env.TOOLIP_REMOTE_VAULT_ENDPOINT;
    delete process.env.TOOLIP_REMOTE_VAULT_TOKEN;
    delete process.env.TOOLIP_REMOTE_VAULT_ENDPOINT;
    const stdout = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      await expect(createProgram().parseAsync([
        ...args, '--enable-network'
      ])).rejects.toThrow('explicit remote-vault');
      expect(stdout).not.toHaveBeenCalled();
    } finally {
      stdout.mockRestore();
      if (before !== undefined) process.env.TOOLIP_REMOTE_VAULT_TOKEN = before;
      else delete process.env.TOOLIP_REMOTE_VAULT_TOKEN;
      if (priorEndpoint !== undefined)
        process.env.TOOLIP_REMOTE_VAULT_ENDPOINT = priorEndpoint;
      else delete process.env.TOOLIP_REMOTE_VAULT_ENDPOINT;
    }
  });

  it('blocks remote writes before any stdin secret collection unless separately approved', async () => {
    const command = [
      'node', 'toolip', 'vault', 'remote', 'set', 'db-password',
      '--provider', 'hashicorp-vault',
      '--project', 'alpha', '--env', 'production',
      '--enable-network'
    ];
    await expect(createProgram().parseAsync(command)).rejects.toThrow(
      'require --confirm-write'
    );
  });

  it('refuses path traversal as a remote secret identity before building a provider', async () => {
    await expect(createProgram().parseAsync([
      'node', 'toolip', 'vault', 'remote', 'get', '../other',
      '--provider', 'hashicorp-vault',
      '--project', 'alpha',
      '--env', 'production',
      '--enable-network'
    ])).rejects.toThrow('bounded canonical segments');
  });
});
