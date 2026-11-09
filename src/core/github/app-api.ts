import { createPrivateKey, createSign } from 'node:crypto';
import type {
  GitHubAppAnnotation,
  GitHubAppRepository,
  GitHubAppScanSummary,
  GitHubAppScanWork
} from './app-webhook.js';
import { redactSensitiveText } from '../safe-output.js';

const API_ORIGIN = 'https://api.github.com';
const API_VERSION = '2022-11-28';
const TOKEN_SAFETY_WINDOW_MS = 60_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const REPOSITORY_NAME = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const SHA = /^[a-f0-9]{40,64}$/iu;

type InstallationToken = { value: string; expiresAt: number };

export type GitHubAppApiClientOptions = {
  appId: string;
  privateKey: string | Buffer;
  fetchImplementation?: typeof fetch;
  now?: () => number;
  requestTimeoutMs?: number;
};

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isRepositoryName(value: string): boolean {
  return (
    REPOSITORY_NAME.test(value) &&
    value.split('/').every((part) => part !== '.' && part !== '..')
  );
}

function checkAnnotations(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) return [];
  const allowedSeverities = new Set([
    'critical',
    'high',
    'medium',
    'low',
    'info'
  ]);
  const output: Array<Record<string, unknown>> = [];
  for (const candidate of value) {
    if (!isRecord(candidate)) continue;
    const annotation = candidate as Partial<GitHubAppAnnotation>;
    const path = annotation.path;
    const ruleId = annotation.ruleId;
    const line = annotation.line;
    const severity = annotation.severity;
    if (
      typeof path !== 'string' ||
      path.length < 1 ||
      path.length > 4_096 ||
      path.includes('\\') ||
      path.includes('\0') ||
      path.startsWith('/') ||
      /^[A-Za-z]:/u.test(path) ||
      path.split('/').some((part) => !part || part === '.' || part === '..') ||
      redactSensitiveText(path) !== path ||
      !Number.isSafeInteger(line) ||
      (line as number) < 1 ||
      (line as number) > 2_147_483_647 ||
      typeof severity !== 'string' ||
      !allowedSeverities.has(severity) ||
      typeof ruleId !== 'string' ||
      !/^[A-Za-z0-9_.:-]{1,128}$/u.test(ruleId) ||
      redactSensitiveText(ruleId) !== ruleId
    )
      continue;
    const level =
      severity === 'critical' || severity === 'high'
        ? 'failure'
        : severity === 'medium'
          ? 'warning'
          : 'notice';
    output.push({
      path,
      start_line: line,
      end_line: line,
      annotation_level: level,
      message: `Toolip reported ${severity} finding ${ruleId}. Review the commit for details.`
    });
  }
  return output.slice(0, 50);
}

async function readJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('github-api-empty-response');
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('github-api-response-too-large');
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(
      Buffer.concat(
        chunks.map((item) => Buffer.from(item)),
        bytes
      )
    )
  ) as unknown;
}

/** GitHub App API client restricted to one allowlisted repository and checks:write. */
export class GitHubAppApiClient {
  private readonly appId: string;
  private readonly privateKey: ReturnType<typeof createPrivateKey>;
  private readonly fetchImplementation: typeof fetch;
  private readonly now: () => number;
  private readonly requestTimeoutMs: number;
  private readonly tokens = new Map<string, InstallationToken>();

  constructor(options: GitHubAppApiClientOptions) {
    if (!/^[1-9][0-9]{0,19}$/u.test(options.appId))
      throw new Error('GitHub App ID is invalid.');
    this.appId = options.appId;
    this.privateKey = createPrivateKey(options.privateKey);
    const modulusLength = this.privateKey.asymmetricKeyDetails?.modulusLength;
    if (
      this.privateKey.asymmetricKeyType !== 'rsa' ||
      !Number.isSafeInteger(modulusLength) ||
      (modulusLength ?? 0) < 2_048
    )
      throw new Error(
        'GitHub App private key must use RSA with at least 2048 bits.'
      );
    this.fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
    this.now = options.now ?? Date.now;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
    if (
      !Number.isSafeInteger(this.requestTimeoutMs) ||
      this.requestTimeoutMs < 1_000 ||
      this.requestTimeoutMs > 60_000
    )
      throw new RangeError(
        'GitHub API timeout must be between 1000 and 60000.'
      );
  }

  /** Creates a minimal checks:write installation token limited to one repository ID. */
  async createSecurityCheck(
    work: GitHubAppScanWork,
    repository: GitHubAppRepository,
    summary: GitHubAppScanSummary,
    signal?: AbortSignal
  ): Promise<void> {
    if (
      work.installationId !== repository.installationId ||
      work.repository !== repository.name.toLowerCase() ||
      work.repositoryId !== repository.repositoryId ||
      !isRepositoryName(repository.name) ||
      !/^[A-Za-z0-9-]{1,128}$/u.test(work.deliveryId) ||
      !['complete', 'incomplete', 'failed'].includes(summary.status) ||
      !Number.isSafeInteger(summary.findingCount) ||
      summary.findingCount < 0
    )
      throw new Error('github-check-identity-mismatch');
    const headSha = summary.revision ?? work.revision;
    if (!headSha || !SHA.test(headSha))
      throw new Error('github-check-revision-unavailable');
    if (
      work.revision &&
      summary.revision &&
      summary.revision.toLowerCase() !== work.revision.toLowerCase()
    )
      throw new Error('github-check-revision-mismatch');
    const [owner, name] = repository.name.split('/');
    if (!owner || !name) throw new Error('github-check-repository-invalid');
    const token = await this.installationToken(repository, signal);
    const conclusion =
      summary.status === 'complete' && summary.findingCount === 0
        ? 'success'
        : 'failure';
    const title =
      summary.status === 'complete'
        ? summary.findingCount === 0
          ? 'Toolip scan completed with no findings'
          : `Toolip found ${Math.min(summary.findingCount, 1_000_000)} issue(s)`
        : `Toolip scan ${summary.status}`;
    const body = {
      name: 'Toolip Security',
      head_sha: headSha.toLowerCase(),
      external_id: work.deliveryId.slice(0, 128),
      status: 'completed',
      conclusion,
      completed_at: new Date(this.now()).toISOString(),
      details_url: 'https://www.zivoralabs.xyz/open-source/toolip/',
      output: {
        title,
        summary:
          summary.status === 'complete'
            ? `Analysis completed. Finding count: ${Math.min(summary.findingCount, 1_000_000)}.`
            : 'Analysis coverage was incomplete or failed. Review the protected runner audit log; this check fails closed.',
        annotations: checkAnnotations(summary.annotations)
      }
    };
    await this.apiRequest(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/check-runs`,
      token,
      { method: 'POST', body: JSON.stringify(body) },
      signal,
      async (response) => {
        if (response.status !== 201) {
          await response.body?.cancel();
          throw new Error('github-check-run-publication-failed');
        }
        await response.body?.cancel();
      }
    );
  }

  private async installationToken(
    repository: GitHubAppRepository,
    signal?: AbortSignal
  ): Promise<string> {
    const key = `${repository.installationId}:${repository.repositoryId}`;
    const cached = this.tokens.get(key);
    if (cached && cached.expiresAt > this.now() + TOKEN_SAFETY_WINDOW_MS)
      return cached.value;
    this.tokens.delete(key);
    const jwt = this.createJwt();
    const document = await this.apiRequest(
      `/app/installations/${repository.installationId}/access_tokens`,
      `Bearer ${jwt}`,
      {
        method: 'POST',
        body: JSON.stringify({
          repository_ids: [repository.repositoryId],
          permissions: { checks: 'write' }
        })
      },
      signal,
      async (response, requestSignal) => {
        if (response.status !== 201) {
          await response.body?.cancel();
          throw new Error('github-installation-token-request-failed');
        }
        try {
          return await readJson(response);
        } catch {
          if (requestSignal.aborted)
            throw new Error('github-api-request-aborted');
          throw new Error('github-installation-token-response-invalid');
        }
      }
    );
    if (
      !isRecord(document) ||
      typeof document.token !== 'string' ||
      document.token.length < 20 ||
      document.token.length > 4_096 ||
      typeof document.expires_at !== 'string' ||
      document.repository_selection !== 'selected' ||
      !Array.isArray(document.repositories) ||
      document.repositories.length !== 1 ||
      !isRecord(document.repositories[0]) ||
      document.repositories[0].id !== repository.repositoryId ||
      !isRecord(document.permissions) ||
      document.permissions.checks !== 'write' ||
      Object.entries(document.permissions).some(
        ([name, permission]) =>
          name !== 'checks' && !(name === 'metadata' && permission === 'read')
      )
    )
      throw new Error('github-installation-token-response-invalid');
    const expiresAt = Date.parse(document.expires_at);
    if (
      !Number.isFinite(expiresAt) ||
      expiresAt <= this.now() + TOKEN_SAFETY_WINDOW_MS
    )
      throw new Error('github-installation-token-expiry-invalid');
    this.tokens.set(key, { value: document.token, expiresAt });
    return document.token;
  }

  private createJwt(): string {
    const nowSeconds = Math.floor(this.now() / 1_000);
    const header = base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = base64Url(
      JSON.stringify({
        iss: this.appId,
        iat: nowSeconds - 30,
        exp: nowSeconds + 8 * 60
      })
    );
    const input = `${header}.${payload}`;
    const signer = createSign('RSA-SHA256');
    signer.update(input);
    signer.end();
    return `${input}.${signer.sign(this.privateKey).toString('base64url')}`;
  }

  private async apiRequest<T>(
    endpoint: string,
    bearer: string,
    request: { method: 'POST'; body: string },
    signal: AbortSignal | undefined,
    consume: (response: Response, signal: AbortSignal) => Promise<T> | T
  ): Promise<T> {
    const controller = new AbortController();
    const onAbort = (): void => controller.abort(signal?.reason);
    let rejectAborted: ((error: Error) => void) | undefined;
    const aborted = new Promise<never>((_resolve, reject) => {
      rejectAborted = reject;
    });
    const onRequestAbort = (): void => {
      rejectAborted?.(new Error('github-api-request-aborted'));
    };
    controller.signal.addEventListener('abort', onRequestAbort, { once: true });
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
    const timeout = setTimeout(
      () => controller.abort(new Error('github-api-timeout')),
      this.requestTimeoutMs
    );
    try {
      const operation = (async (): Promise<T> => {
        const response = await this.fetchImplementation(
          `${API_ORIGIN}${endpoint}`,
          {
            method: request.method,
            body: request.body,
            redirect: 'error',
            signal: controller.signal,
            headers: {
              accept: 'application/vnd.github+json',
              authorization: bearer.startsWith('Bearer ')
                ? bearer
                : `Bearer ${bearer}`,
              'content-type': 'application/json',
              'user-agent': 'toolip-github-app',
              'x-github-api-version': API_VERSION
            }
          }
        );
        if (response.url && new URL(response.url).origin !== API_ORIGIN) {
          await response.body?.cancel();
          throw new Error('github-api-origin-invalid');
        }
        return await consume(response, controller.signal);
      })();
      return await Promise.race([operation, aborted]);
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', onAbort);
      controller.signal.removeEventListener('abort', onRequestAbort);
    }
  }
}
