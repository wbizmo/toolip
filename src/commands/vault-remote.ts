import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import {
  hashicorpVaultProvider,
  onePasswordConnectProvider,
  type VaultAccess,
  type VaultIdentity,
  type VaultOperation,
  type VaultProvider
} from '../vault/providers/index.js';
import { readSecretInputs } from '../utils/secret-input.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

const segment = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
type RemoteVaultProviderName = 'hashicorp-vault' | '1password-connect';
type RemoteOptions = {
  provider: string;
  project: string;
  env: string;
  enableNetwork?: boolean;
  reveal?: boolean;
  confirmWrite?: boolean;
};

/**
 * Remote credentials and endpoint configuration are exclusively host-owned
 * environment inputs. Never accept tokens or secret values through argv,
 * scanned manifests, MCP resources, AI advice or arbitrary project scripts.
 */
export function configuredRemoteVault(input: Readonly<{
  provider: string;
  identity: VaultIdentity;
  env: NodeJS.ProcessEnv;
  operations?: readonly VaultOperation[];
}>): Readonly<{ provider: VaultProvider; access: VaultAccess }> {
  const { identity, env } = input;
  const endpoint = env.TOOLIP_REMOTE_VAULT_ENDPOINT;
  const token = env.TOOLIP_REMOTE_VAULT_TOKEN;
  const configured = Boolean(endpoint && token);
  if (
    !configured ||
    ![identity.project, identity.environment, identity.name]
      .every((value) => typeof value === 'string' && segment.test(value)) ||
    !['hashicorp-vault', '1password-connect'].includes(input.provider)
  )
    throw new ToolipError(
      'An explicit remote-vault provider, scoped identity, HTTPS endpoint and operator token are required.',
      { code: 'REMOTE_VAULT_CONFIGURATION_INVALID', exitCode: 1 }
    );

  let provider: VaultProvider;
  if (input.provider === 'hashicorp-vault') {
    if (!env.TOOLIP_REMOTE_VAULT_MOUNT ||
        !segment.test(env.TOOLIP_REMOTE_VAULT_MOUNT))
      throw new ToolipError(
        'An explicit remote-vault mount is required.',
        { code: 'REMOTE_VAULT_CONFIGURATION_INVALID', exitCode: 1 }
      );
    provider = hashicorpVaultProvider({
      endpoint: endpoint!,
      token: env.TOOLIP_REMOTE_VAULT_TOKEN!,
      mount: env.TOOLIP_REMOTE_VAULT_MOUNT
    });
  } else {
    if (
      !env.TOOLIP_REMOTE_VAULT_ID ||
      !env.TOOLIP_REMOTE_ITEM_ID ||
      !/^[A-Za-z0-9-]{4,128}$/u.test(env.TOOLIP_REMOTE_VAULT_ID) ||
      !/^[A-Za-z0-9-]{4,128}$/u.test(env.TOOLIP_REMOTE_ITEM_ID)
    )
      throw new ToolipError(
        'An explicitly scoped 1Password vault and item ID are required.',
        { code: 'REMOTE_VAULT_CONFIGURATION_INVALID', exitCode: 1 }
      );
    const identityKey =
      `${identity.project}/${identity.environment}/${identity.name}`;
    provider = onePasswordConnectProvider({
      endpoint: endpoint!,
      token: env.TOOLIP_REMOTE_VAULT_TOKEN!,
      vaultId: env.TOOLIP_REMOTE_VAULT_ID,
      itemIds: { [identityKey]: env.TOOLIP_REMOTE_ITEM_ID }
    });
  }
  return Object.freeze({
    provider,
    access: Object.freeze({
      project: identity.project,
      environments: Object.freeze([identity.environment]),
      operations: Object.freeze(input.operations ?? ['read'])
    })
  });
}

function identityFrom(name: string, options: RemoteOptions): VaultIdentity {
  const identity = {
    project: options.project,
    environment: options.env,
    name
  };
  if (!Object.values(identity).every((part) =>
    typeof part === 'string' && segment.test(part)
  ))
    throw new ToolipError(
      'Remote vault identifiers must be bounded canonical segments.',
      { code: 'REMOTE_VAULT_IDENTITY_INVALID', exitCode: 1 }
    );
  return identity;
}

function requireNetworkConsent(options: RemoteOptions): void {
  if (options.enableNetwork !== true)
    throw new ToolipError(
      'External vault access requires explicit --enable-network consent.',
      { code: 'REMOTE_VAULT_NETWORK_CONSENT_REQUIRED', exitCode: 1 }
    );
}

function identityOptions(command: Command): Command {
  return command
    .requiredOption(
      '--provider <kind>',
      'Explicit HashiCorp Vault or 1Password Connect provider.'
    )
    .requiredOption('--project <id>', 'Exact authorized project namespace.')
    .requiredOption('--env <id>', 'Exact authorized environment namespace.')
    .option('--enable-network', 'Consent to contact the selected external vault.');
}

/**
 * The default `toolip vault` remains locally encrypted. No external provider
 * is used unless the operator explicitly enters `vault remote` and consents.
 */
export function registerVaultRemoteCommands(vault: Command): void {
  const remote = vault
    .command('remote')
    .description(
      'Explicit external vault access. Reads provider credentials from the host environment, not argv.'
    );

  identityOptions(
    remote.command('get <name>')
      .description('Read a scoped remote secret; value hidden unless --reveal is explicitly set.')
  )
    .option('--reveal', 'Explicitly print secret text to stdout (may be recorded by the caller).')
    .action(async (name: string, options: RemoteOptions) => {
      requireNetworkConsent(options);
      const identity = identityFrom(name, options);
      const { provider, access } = configuredRemoteVault({
        provider: options.provider, identity, env: process.env
      });
      const secret = await provider.get(identity, access);
      if (options.reveal === true)
        process.stdout.write(secret + '\n');
      else
        console.log(serializeJsonOutputBounded({
          status: 'retrieved', provider: provider.provider,
          valueRevealed: false, encryptedLocalVaultFallback: false
        }));
    });

  identityOptions(
    remote.command('set <name>')
      .description('Store a scoped remote secret, read privately from prompt/stdin.')
  )
    .option('--confirm-write', 'Explicit permission to create or replace this one remote secret.')
    .action(async (name: string, options: RemoteOptions) => {
      requireNetworkConsent(options);
      if (options.confirmWrite !== true)
        throw new ToolipError(
          'Remote writes require --confirm-write and manual approval.',
          { code: 'REMOTE_VAULT_WRITE_CONSENT_REQUIRED', exitCode: 1 }
        );
      const identity = identityFrom(name, options);
      const { provider, access } = configuredRemoteVault({
        provider: options.provider,
        identity,
        env: process.env,
        operations: ['write']
      });
      if (!provider.set)
        throw new ToolipError(
          'This external vault provider does not implement reviewed writes.',
          { code: 'REMOTE_VAULT_CAPABILITY_UNAVAILABLE', exitCode: 1 }
        );
      const [value] = await readSecretInputs(['Secret value']);
      await provider.set(identity, value, access);
      console.log(serializeJsonOutputBounded({
        status: 'stored', provider: provider.provider,
        valueRevealed: false, encryptedLocalVaultFallback: false
      }));
    });
}
