/** Scoped, opt-in external vault providers. The existing encrypted local
 * vault remains the default; there is never an implicit cross-provider fallback.
 */
export type VaultOperation = 'read' | 'write';

export type VaultIdentity = Readonly<{
  project: string;
  environment: string;
  name: string;
}>;

export type VaultAccess = Readonly<{
  project: string;
  environments: readonly string[];
  operations: readonly VaultOperation[];
  signal?: AbortSignal;
}>;

export interface VaultProvider {
  readonly provider: 'hashicorp-vault' | '1password-connect' | 'aws-secrets-manager';
  get(identity: VaultIdentity, access: VaultAccess): Promise<string>;
  set?(identity: VaultIdentity, value: string, access: VaultAccess): Promise<void>;
}

const validSegment = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

function authorized(
  identity: VaultIdentity, access: VaultAccess, operation: VaultOperation
): void {
  if (![identity.project, identity.environment, identity.name].every(
    (segment) => typeof segment === 'string' && validSegment.test(segment)
  ))
    throw new Error('Vault identity must use bounded canonical segments.');
  if (access.project !== identity.project ||
      !access.environments.includes(identity.environment) ||
      !access.operations.includes(operation))
    throw new Error('Vault access denied for this project/environment/operation.');
  if (access.signal?.aborted)
    throw new Error('Vault request was cancelled.');
}

function trustedEndpoint(input: string): URL {
  const endpoint = new URL(input);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password ||
      endpoint.search || endpoint.hash)
    throw new Error('External vault requires an explicitly configured credential-free HTTPS URL.');
  if (endpoint.port && endpoint.port !== '443')
    throw new Error('External vault endpoint has an unsupported port.');
  return endpoint;
}

async function boundedVaultJson(
  url: URL,
  init: RequestInit,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch
): Promise<Record<string, unknown>> {
  const abort = new AbortController();
  const onAbort = () => abort.abort(signal?.reason);
  signal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => abort.abort(), 5_000);
  try {
    const response = await fetcher(url, {
      ...init,
      redirect: 'error',
      signal: abort.signal
    });
    if (!response.ok)
      throw new Error('External vault request was refused.');
    if (Number(response.headers.get('content-length')) > 256 * 1024)
      throw new Error('External vault response exceeds bounded size.');
    if (!response.body) throw new Error('External vault response was empty.');
    const reader = response.body.getReader();
    let total = 0;
    const fragments: Uint8Array[] = [];
    try {
      while (true) {
        const current = await reader.read();
        if (current.done) break;
        total += current.value.byteLength;
        if (total > 256 * 1024)
          throw new Error('External vault response exceeds bounded size.');
        fragments.push(current.value);
      }
    } finally {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
    const data = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(fragments, total))
    ) as unknown;
    if (!data || typeof data !== 'object' || Array.isArray(data))
      throw new Error('External vault response was malformed.');
    return data as Record<string, unknown>;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

function nestedRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

export function hashicorpVaultProvider(
  input: {
    endpoint: string;
    token: string;
    mount: string;
    fetcher?: typeof fetch;
  }
): VaultProvider {
  const endpoint = trustedEndpoint(input.endpoint);
  if (!validSegment.test(input.mount) || !input.token || /[\r\n]/u.test(input.token))
    throw new Error('Invalid HashiCorp Vault mount or token.');
  const address = (identity: VaultIdentity): URL =>
    new URL(
      `/v1/${input.mount}/data/${identity.project}/${identity.environment}/${identity.name}`,
      endpoint
    );
  return {
    provider: 'hashicorp-vault',
    async get(identity, access) {
      authorized(identity, access, 'read');
      const response = await boundedVaultJson(address(identity), {
        method: 'GET', headers: { 'X-Vault-Token': input.token }
      }, access.signal, input.fetcher);
      const stored = nestedRecord(nestedRecord(response.data)?.data);
      if (typeof stored?.value !== 'string')
        throw new Error('HashiCorp Vault secret was unavailable.');
      return stored.value;
    },
    async set(identity, value, access) {
      authorized(identity, access, 'write');
      if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 64 * 1024)
        throw new RangeError('External vault secret is not a bounded string.');
      await boundedVaultJson(address(identity), {
        method: 'POST',
        headers: {
          'X-Vault-Token': input.token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ data: { value } })
      }, access.signal, input.fetcher);
    }
  };
}

export function onePasswordConnectProvider(
  input: {
    endpoint: string;
    token: string;
    vaultId: string;
    itemIds: Readonly<Record<string, string>>;
    fetcher?: typeof fetch;
  }
): VaultProvider {
  const endpoint = trustedEndpoint(input.endpoint);
  if (!/^[A-Za-z0-9-]{4,128}$/u.test(input.vaultId) ||
      !input.token || /[\r\n]/u.test(input.token))
    throw new Error('Invalid 1Password Connect credentials or vault ID.');
  return {
    provider: '1password-connect',
    async get(identity, access) {
      authorized(identity, access, 'read');
      const key = `${identity.project}/${identity.environment}/${identity.name}`;
      // The operator maintains the allowlist. No enumerating arbitrary vault
      // entries or using untrusted item IDs supplied by a scanned project.
      const itemId = input.itemIds[key];
      if (!itemId || !/^[A-Za-z0-9-]{4,128}$/u.test(itemId))
        throw new Error('1Password Connect item is not explicitly authorized.');
      const url = new URL(`/v1/vaults/${input.vaultId}/items/${itemId}`, endpoint);
      const item = await boundedVaultJson(url, {
        method: 'GET', headers: { Authorization: `Bearer ${input.token}` }
      }, access.signal, input.fetcher);
      const fields = item.fields;
      if (!Array.isArray(fields) || fields.length > 128)
        throw new Error('1Password Connect response has invalid fields.');
      const secret = fields.find((field) =>
        nestedRecord(field)?.id === 'password' ||
        nestedRecord(field)?.purpose === 'PASSWORD'
      );
      const value = nestedRecord(secret)?.value;
      if (typeof value !== 'string')
        throw new Error('1Password Connect secret field was unavailable.');
      return value;
    }
  };
}

export type AwsSecretsManagerClient = Readonly<{
  getSecretValue(input: {
    SecretId: string;
    abortSignal?: AbortSignal;
  }): Promise<{ SecretString?: string }>;
  putSecretValue(input: {
    SecretId: string;
    SecretString: string;
    abortSignal?: AbortSignal;
  }): Promise<unknown>;
}>;

/** SDK-neutral adapter: caller supplies an authenticated, region-scoped AWS
 * client. No process shell, credential lookup, or dynamic package loading.
 */
export function awsSecretsManagerProvider(
  client: AwsSecretsManagerClient,
  trustedPrefix: string
): VaultProvider {
  if (!/^[A-Za-z0-9._/-]{1,128}$/u.test(trustedPrefix) ||
      trustedPrefix.includes('..'))
    throw new Error('Invalid configured AWS secret prefix.');
  const identifier = (identity: VaultIdentity) =>
    `${trustedPrefix.replace(/\/$/u, '')}/${identity.project}/${identity.environment}/${identity.name}`;
  return {
    provider: 'aws-secrets-manager',
    async get(identity, access) {
      authorized(identity, access, 'read');
      const response = await client.getSecretValue({
        SecretId: identifier(identity), abortSignal: access.signal
      });
      if (typeof response.SecretString !== 'string')
        throw new Error('AWS Secrets Manager secret was unavailable.');
      return response.SecretString;
    },
    async set(identity, value, access) {
      authorized(identity, access, 'write');
      if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 64 * 1024)
        throw new RangeError('External vault secret is not a bounded string.');
      await client.putSecretValue({
        SecretId: identifier(identity), SecretString: value,
        abortSignal: access.signal
      });
    }
  };
}
