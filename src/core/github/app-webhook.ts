import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { realpath } from 'node:fs/promises';
import { buildSecurityScorecard } from '../../application/security-scorecard.js';
import {
  createProjectSnapshot,
  verifyProjectSnapshot
} from '../../application/project-snapshot.js';
import { runGit, runGitChecked } from '../git/safe-git.js';
import { redactSensitiveText } from '../safe-output.js';
import { GitHubAppDeliveryJournal } from './delivery-journal.js';

const REPOSITORY_NAME = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const COMMIT_SHA = /^[a-f0-9]{40,64}$/iu;
const SHA = COMMIT_SHA;
const DELIVERY_ID = /^[A-Za-z0-9-]{1,128}$/u;
const MAX_BODY_BYTES = 1_048_576;
const DEFAULT_DEDUPE_LIMIT = 10_000;
const DEFAULT_DEDUPE_TTL_MS = 24 * 60 * 60 * 1_000;
const MAX_SNAPSHOT_TREE_BYTES = 16 * 1024 * 1024;
const MAX_SNAPSHOT_FILES = 20_000;
const MAX_SNAPSHOT_BLOB_BYTES = 64 * 1024 * 1024;

export type GitHubAppRepository = Readonly<{
  name: string;
  installationId: number;
  repositoryId: number;
  root: string;
}>;

export type GitHubAppScanWork = Readonly<{
  kind: 'push' | 'scheduled';
  installationId: number;
  repository: string;
  repositoryId: number;
  revision?: string;
  ref?: string;
  deliveryId: string;
}>;

export type GitHubAppScanSummary = Readonly<{
  status: 'complete' | 'incomplete' | 'failed';
  findingCount: number;
  annotations?: readonly GitHubAppAnnotation[];
  snapshotId?: string;
  revision?: string;
  reason?: string;
}>;

/** Deliberately excludes finding text and snippets from GitHub annotations. */
export type GitHubAppAnnotation = Readonly<{
  path: string;
  line: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  ruleId: string;
}>;

export type GitHubAppWebhookOptions = {
  webhookSecret: string | Buffer;
  repositories: readonly GitHubAppRepository[];
  scan: (
    work: GitHubAppScanWork,
    repository: GitHubAppRepository,
    signal: AbortSignal
  ) => Promise<GitHubAppScanSummary>;
  audit?: (entry: Readonly<Record<string, unknown>>) => void | Promise<void>;
  publishResult?: (
    work: GitHubAppScanWork,
    repository: GitHubAppRepository,
    summary: GitHubAppScanSummary,
    signal: AbortSignal
  ) => Promise<void>;
  maxConcurrentScans?: number;
  maxQueuedScans?: number;
  scanTimeoutMs?: number;
  dedupeLimit?: number;
  dedupeTtlMs?: number;
  maxBodyBytes?: number;
  stateFile?: string;
};

type DeliveryRecord = { state: 'pending' | 'complete'; expiresAt: number };
type ScheduledServer = Pick<
  Server,
  | 'close'
  | 'address'
  | 'headersTimeout'
  | 'requestTimeout'
  | 'maxHeadersCount'
  | 'maxConnections'
>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isRepositoryName(value: string): boolean {
  if (!REPOSITORY_NAME.test(value)) return false;
  return value.split('/').every((part) => part !== '.' && part !== '..');
}

function positiveInteger(value: number, fallback: number, max: number): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > max)
    throw new RangeError(
      'GitHub App resource limit is outside supported bounds.'
    );
  return selected;
}

function settleOnAbort<T>(
  operation: Promise<T>,
  signal: AbortSignal,
  fallback: T
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => signal.removeEventListener('abort', onAbort);
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(fallback);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    operation.then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      }
    );
  });
}

type CommitTreeBlob = Readonly<{
  mode: string;
  oid: string;
  path: string;
}>;

function parseCommitTree(
  output: Buffer
): { ok: true; blobs: CommitTreeBlob[] } | { ok: false; reason: string } {
  if (output.byteLength > MAX_SNAPSHOT_TREE_BYTES)
    return { ok: false, reason: 'repository-tree-budget-exceeded' };
  if (output.byteLength > 0 && output[output.byteLength - 1] !== 0)
    return { ok: false, reason: 'repository-tree-truncated' };

  const decoder = new TextDecoder('utf-8', { fatal: true });
  const blobs: CommitTreeBlob[] = [];
  let offset = 0;
  while (offset < output.byteLength) {
    const end = output.indexOf(0, offset);
    const tab = output.indexOf(9, offset);
    if (end < 0 || tab < 0 || tab >= end)
      return { ok: false, reason: 'repository-tree-malformed' };
    const metadata = output.subarray(offset, tab).toString('ascii');
    const match = metadata.match(
      /^([0-7]{6}) (blob|commit) ([a-f0-9]{40,64})$/u
    );
    if (!match?.[1] || !match[2] || !match[3])
      return { ok: false, reason: 'repository-tree-malformed' };
    let entryPath: string;
    try {
      const pathBytes = output.subarray(tab + 1, end);
      entryPath = decoder.decode(pathBytes);
      if (!Buffer.from(entryPath, 'utf8').equals(pathBytes))
        return { ok: false, reason: 'repository-tree-path-invalid' };
    } catch {
      return { ok: false, reason: 'repository-tree-path-invalid' };
    }
    if (
      !entryPath ||
      entryPath.includes('\\') ||
      entryPath.startsWith('/') ||
      entryPath
        .split('/')
        .some((part) => !part || part === '.' || part === '..')
    )
      return { ok: false, reason: 'repository-tree-path-invalid' };
    if (match[2] !== 'blob')
      return {
        ok: false,
        reason: 'repository-tree-contains-link-or-submodule'
      };
    if (match[1] !== '100644' && match[1] !== '100755')
      return { ok: false, reason: 'repository-tree-mode-unsupported' };
    blobs.push({
      mode: match[1],
      oid: match[3].toLowerCase(),
      path: entryPath
    });
    if (blobs.length > MAX_SNAPSHOT_FILES)
      return { ok: false, reason: 'repository-tree-file-budget-exceeded' };
    offset = end + 1;
  }
  return { ok: true, blobs };
}

function parseCommitBlobs(
  output: Buffer,
  oids: readonly string[],
  maximumBytes: number
): Map<string, { sha256: string; bytes: number }> | undefined {
  const content = new Map<string, { sha256: string; bytes: number }>();
  let offset = 0;
  let total = 0;
  for (const oid of oids) {
    const headerEnd = output.indexOf(10, offset);
    if (headerEnd < 0) return undefined;
    const header = output.subarray(offset, headerEnd).toString('ascii');
    const match = header.match(/^([a-f0-9]{40,64}) blob ([0-9]+)$/u);
    if (!match || match[1]?.toLowerCase() !== oid) return undefined;
    const size = Number(match[2]);
    if (!Number.isSafeInteger(size) || size < 0 || size > maximumBytes)
      return undefined;
    total += size;
    if (total > maximumBytes) return undefined;
    const start = headerEnd + 1;
    const end = start + size;
    if (end >= output.byteLength || output[end] !== 10) return undefined;
    const bytes = output.subarray(start, end);
    content.set(oid, {
      sha256: createHash('sha256').update(bytes).digest('hex'),
      bytes: size
    });
    offset = end + 1;
  }
  return offset === output.byteLength ? content : undefined;
}

/** Proves snapshot coverage and bytes against regular blobs in one exact Git tree. */
async function verifySnapshotMatchesCommit(
  root: string,
  revision: string,
  snapshot: Awaited<ReturnType<typeof createProjectSnapshot>>,
  signal: AbortSignal
): Promise<{ matches: true } | { matches: false; reason: string }> {
  try {
    const prefix = await runGitChecked(['rev-parse', '--show-prefix'], {
      cwd: root,
      signal,
      timeoutMs: 5_000,
      maxBuffer: 4_096
    });
    if (prefix.toString('utf8').trim().length !== 0)
      return { matches: false, reason: 'repository-root-not-top-level' };
    const treeOutput = await runGitChecked(
      ['--no-replace-objects', 'ls-tree', '-r', '-z', '--full-tree', revision],
      {
        cwd: root,
        signal,
        timeoutMs: 30_000,
        maxBuffer: MAX_SNAPSHOT_TREE_BYTES
      }
    );
    const tree = parseCommitTree(treeOutput);
    if (!tree.ok) return { matches: false, reason: tree.reason };
    if (tree.blobs.length !== snapshot.files.length)
      return {
        matches: false,
        reason: 'repository-snapshot-file-set-mismatch'
      };

    const captured = new Map(snapshot.files.map((file) => [file.path, file]));
    if (captured.size !== snapshot.files.length)
      return { matches: false, reason: 'repository-snapshot-path-duplicate' };
    const oids: string[] = [];
    const treeByPath = new Map<string, CommitTreeBlob>();
    for (const blob of tree.blobs) {
      if (treeByPath.has(blob.path))
        return { matches: false, reason: 'repository-tree-path-duplicate' };
      treeByPath.set(blob.path, blob);
      if (!captured.has(blob.path))
        return {
          matches: false,
          reason: 'repository-snapshot-file-set-mismatch'
        };
      oids.push(blob.oid);
    }
    const uniqueOids = [...new Set(oids)];
    const output = await runGitChecked(
      ['--no-replace-objects', 'cat-file', '--batch'],
      {
        cwd: root,
        signal,
        timeoutMs: 30_000,
        maxBuffer: MAX_SNAPSHOT_BLOB_BYTES + uniqueOids.length * 128,
        input: `${uniqueOids.join('\n')}\n`
      }
    );
    const gitContent = parseCommitBlobs(
      output,
      uniqueOids,
      Math.min(snapshot.budgets.maxTotalBytes, MAX_SNAPSHOT_BLOB_BYTES)
    );
    if (!gitContent)
      return {
        matches: false,
        reason: 'repository-snapshot-blob-budget-or-read-failed'
      };
    for (const [relativePath, blob] of treeByPath) {
      const file = captured.get(relativePath);
      const committed = gitContent.get(blob.oid);
      if (
        !file ||
        !committed ||
        file.bytes !== committed.bytes ||
        file.sha256 !== committed.sha256
      )
        return {
          matches: false,
          reason: 'repository-snapshot-content-mismatch'
        };
      if (blob.mode === '100755' && file.binary)
        return {
          matches: false,
          reason: 'repository-executable-binary-uninspected'
        };
      if (
        file.content?.startsWith('version https://git-lfs.github.com/spec/v1\n')
      )
        return { matches: false, reason: 'repository-lfs-object-unavailable' };
    }
    return { matches: true };
  } catch {
    return {
      matches: false,
      reason: signal.aborted
        ? 'repository-snapshot-verification-cancelled'
        : 'repository-snapshot-verification-unavailable'
    };
  }
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: Record<string, unknown>
): void {
  const text = JSON.stringify(body);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  response.end(text);
}

async function readRequestBody(
  request: IncomingMessage,
  maximum: number
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > maximum) {
      request.destroy();
      throw new Error('webhook-body-too-large');
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, size);
}

function verifySignature(
  secret: Buffer,
  rawBody: Buffer,
  signature: string | undefined
): boolean {
  if (!signature || !/^sha256=[a-f0-9]{64}$/iu.test(signature)) return false;
  const supplied = Buffer.from(signature.slice('sha256='.length), 'hex');
  const expected = createHmac('sha256', secret).update(rawBody).digest();
  return (
    supplied.length === expected.length && timingSafeEqual(supplied, expected)
  );
}

function safeAnnotationPath(value: unknown): string | undefined {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 4_096 ||
    value.includes('\\') ||
    value.includes('\0') ||
    value.startsWith('/') ||
    /^[A-Za-z]:/u.test(value) ||
    redactSensitiveText(value) !== value
  )
    return undefined;
  const parts = value.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..'))
    return undefined;
  return value;
}

function normalizeAnnotations(value: unknown): GitHubAppAnnotation[] {
  if (!Array.isArray(value)) return [];
  const annotations: GitHubAppAnnotation[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const filePath = safeAnnotationPath(item.path);
    const severity = item.severity;
    const ruleId = item.ruleId;
    const line = item.line;
    if (
      !filePath ||
      !Number.isSafeInteger(line) ||
      (line as number) < 1 ||
      (line as number) > 2_147_483_647 ||
      !['critical', 'high', 'medium', 'low', 'info'].includes(
        String(severity)
      ) ||
      typeof ruleId !== 'string' ||
      !/^[A-Za-z0-9_.:-]{1,128}$/u.test(ruleId) ||
      redactSensitiveText(ruleId) !== ruleId
    )
      continue;
    annotations.push({
      path: filePath,
      line: line as number,
      severity: severity as GitHubAppAnnotation['severity'],
      ruleId
    });
  }
  annotations.sort(
    (left, right) =>
      left.path.localeCompare(right.path) ||
      left.line - right.line ||
      left.ruleId.localeCompare(right.ruleId)
  );
  return annotations.slice(0, 50);
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return typeof value === 'string' ? value : undefined;
}

function installationId(payload: Record<string, unknown>): number | undefined {
  const installation = payload.installation;
  if (!isRecord(installation)) return undefined;
  const id = installation.id;
  return Number.isSafeInteger(id) && (id as number) > 0
    ? (id as number)
    : undefined;
}

function repositoryIdentity(
  payload: Record<string, unknown>
): { name: string; repositoryId: number } | undefined {
  const repository = payload.repository;
  if (!isRecord(repository) || typeof repository.full_name !== 'string')
    return undefined;
  const name = repository.full_name;
  const repositoryId = repository.id;
  return isRepositoryName(name) &&
    Number.isSafeInteger(repositoryId) &&
    (repositoryId as number) > 0
    ? { name: name.toLowerCase(), repositoryId: repositoryId as number }
    : undefined;
}

function workFromEvent(
  event: string,
  payload: Record<string, unknown>,
  deliveryId: string
):
  | GitHubAppScanWork
  | 'ignored'
  | 'installation-suspended'
  | 'installation-active'
  | undefined {
  if (event === 'ping') return 'ignored';
  const id = installationId(payload);
  if (id === undefined) return undefined;
  if (event === 'installation') {
    const action = payload.action;
    if (action === 'suspend' || action === 'deleted')
      return 'installation-suspended';
    if (action === 'unsuspend' || action === 'created')
      return 'installation-active';
    return undefined;
  }
  const repository = repositoryIdentity(payload);
  if (!repository) return undefined;
  if (event === 'push') {
    if (payload.deleted === true) return 'ignored';
    const revision = payload.after;
    const ref = payload.ref;
    if (
      typeof revision !== 'string' ||
      !COMMIT_SHA.test(revision) ||
      typeof ref !== 'string' ||
      !/^refs\/heads\/[A-Za-z0-9._/-]{1,240}$/u.test(ref) ||
      ref.includes('..')
    )
      return undefined;
    return {
      kind: 'push',
      installationId: id,
      repository: repository.name,
      repositoryId: repository.repositoryId,
      revision: revision.toLowerCase(),
      ref,
      deliveryId
    };
  }
  if (event === 'repository_dispatch') {
    if (payload.action !== 'toolip-scan') return 'ignored';
    const clientPayload = payload.client_payload;
    const revision = isRecord(clientPayload)
      ? clientPayload.revision
      : undefined;
    if (typeof revision !== 'string' || !COMMIT_SHA.test(revision))
      return undefined;
    return {
      kind: 'push',
      installationId: id,
      repository: repository.name,
      repositoryId: repository.repositoryId,
      revision: revision.toLowerCase(),
      deliveryId
    };
  }
  return 'ignored';
}

/**
 * Signed-webhook ingress for opt-in, read-only GitHub App scans. The host must
 * provision an exact local commit; this service never clones, checks out,
 * installs, builds, comments on, or writes to a repository.
 */
export class GitHubAppWebhookService {
  private readonly secret: Buffer;
  private readonly repositories = new Map<string, GitHubAppRepository>();
  private readonly suspendedInstallations = new Set<number>();
  private readonly pendingSuspensions = new Set<number>();
  private readonly scheduledRepositories = new Set<string>();
  private readonly deliveries = new Map<string, DeliveryRecord>();
  private readonly queue: Array<{
    work: GitHubAppScanWork;
    repository: GitHubAppRepository;
  }> = [];
  private readonly concurrency: number;
  private readonly queueLimit: number;
  private readonly scanTimeoutMs: number;
  private readonly dedupeLimit: number;
  private readonly dedupeTtlMs: number;
  private readonly journal?: GitHubAppDeliveryJournal;
  private readonly maxBodyBytes: number;
  private readonly audit: NonNullable<GitHubAppWebhookOptions['audit']>;
  private active = 0;
  private closed = false;
  private readonly activeControllers = new Set<AbortController>();
  private readonly controllerInstallations = new Map<AbortController, number>();
  private readonly server: Server;

  constructor(private readonly options: GitHubAppWebhookOptions) {
    this.secret = Buffer.isBuffer(options.webhookSecret)
      ? Buffer.from(options.webhookSecret)
      : Buffer.from(options.webhookSecret, 'utf8');
    if (this.secret.byteLength < 32)
      throw new Error(
        'GitHub App webhook secret must contain at least 32 bytes.'
      );
    if (!options.repositories.length || options.repositories.length > 100)
      throw new Error('Configure between 1 and 100 GitHub App repositories.');
    for (const repository of options.repositories) {
      const name = repository.name.toLowerCase();
      if (
        !isRepositoryName(repository.name) ||
        !Number.isSafeInteger(repository.installationId) ||
        repository.installationId < 1 ||
        !Number.isSafeInteger(repository.repositoryId) ||
        repository.repositoryId < 1 ||
        !path.isAbsolute(repository.root) ||
        this.repositories.has(name)
      )
        throw new Error('GitHub App repository allowlist is invalid.');
      this.repositories.set(name, Object.freeze({ ...repository, name }));
    }
    this.concurrency = positiveInteger(options.maxConcurrentScans ?? 2, 2, 16);
    this.queueLimit = positiveInteger(options.maxQueuedScans ?? 64, 64, 1_000);
    this.scanTimeoutMs = positiveInteger(
      options.scanTimeoutMs ?? 120_000,
      120_000,
      600_000
    );
    this.dedupeLimit = positiveInteger(
      options.dedupeLimit ?? DEFAULT_DEDUPE_LIMIT,
      DEFAULT_DEDUPE_LIMIT,
      100_000
    );
    this.dedupeTtlMs = positiveInteger(
      options.dedupeTtlMs ?? DEFAULT_DEDUPE_TTL_MS,
      DEFAULT_DEDUPE_TTL_MS,
      30 * 24 * 60 * 60 * 1_000
    );
    this.journal = options.stateFile
      ? new GitHubAppDeliveryJournal(options.stateFile)
      : undefined;
    this.maxBodyBytes = positiveInteger(
      options.maxBodyBytes ?? MAX_BODY_BYTES,
      MAX_BODY_BYTES,
      8 * 1024 * 1024
    );
    this.audit = options.audit ?? (() => undefined);
    this.server = createServer((request, response) => {
      void this.handleRequest(request, response);
    });
    // Bound unauthenticated connections and time spent waiting for headers or
    // a complete signed body. Byte limits alone do not stop slow clients from
    // occupying sockets indefinitely before HMAC verification can run.
    this.server.headersTimeout = 10_000;
    this.server.requestTimeout = 30_000;
    this.server.maxHeadersCount = 100;
    this.server.maxConnections = 128;
  }

  listen(port: number, host = '127.0.0.1'): Promise<ScheduledServer> {
    if (this.closed) throw new Error('GitHub App webhook service is closed.');
    if (!Number.isSafeInteger(port) || port < 0 || port > 65_535)
      throw new RangeError('Webhook port must be between 0 and 65535.');
    return this.refreshPersistentState().then(
      () =>
        new Promise((resolve, reject) => {
          const onError = (error: Error): void => reject(error);
          this.server.once('error', onError);
          this.server.listen(port, host, () => {
            this.server.off('error', onError);
            resolve(this.server as ScheduledServer);
          });
        })
    );
  }

  /** Enqueues an allowlisted repository's current local HEAD for a scheduled scan. */
  schedule(repositoryNameValue: string): boolean {
    const repository = this.repositories.get(repositoryNameValue.toLowerCase());
    if (
      this.closed ||
      !repository ||
      this.suspendedInstallations.has(repository.installationId) ||
      this.scheduledRepositories.has(repository.name) ||
      this.queue.length >= this.queueLimit
    )
      return false;
    const deliveryId = `scheduled-${randomUUID()}`;
    const work = Object.freeze({
      kind: 'scheduled' as const,
      installationId: repository.installationId,
      repository: repository.name,
      repositoryId: repository.repositoryId,
      deliveryId
    });
    this.queue.push({ work, repository });
    this.scheduledRepositories.add(repository.name);
    this.rememberDelivery(deliveryId, 'pending');
    this.pump();
    return true;
  }

  scheduleAll(): number {
    let queued = 0;
    for (const name of this.repositories.keys())
      if (this.schedule(name)) queued++;
    return queued;
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const controller of this.activeControllers)
      controller.abort(new Error('GitHub App service is shutting down.'));
    for (const item of this.queue.splice(0)) {
      if (item.work.kind === 'scheduled')
        this.scheduledRepositories.delete(item.work.repository);
      this.rememberDelivery(item.work.deliveryId, 'complete');
      void this.writeAudit({
        event: 'scan-cancelled',
        reason: 'service-shutdown',
        repository: item.work.repository,
        deliveryId: item.work.deliveryId
      });
    }
    if (!this.server.listening) return;
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  private async handleRequest(
    request: IncomingMessage,
    response: ServerResponse
  ): Promise<void> {
    if (
      request.method !== 'POST' ||
      request.url?.split('?', 1)[0] !== '/webhook'
    ) {
      sendJson(response, 404, { accepted: false });
      return;
    }
    let body: Buffer;
    try {
      body = await readRequestBody(request, this.maxBodyBytes);
    } catch {
      if (!response.destroyed && !response.headersSent)
        sendJson(response, 413, { accepted: false, reason: 'body-too-large' });
      return;
    }
    let result: { status: number; body: Record<string, unknown> };
    try {
      result = await this.receiveWebhook({
        body,
        signature: header(request, 'x-hub-signature-256'),
        deliveryId: header(request, 'x-github-delivery'),
        event: header(request, 'x-github-event')
      });
    } catch {
      result = {
        status: 503,
        body: { accepted: false, reason: 'delivery-state-unavailable' }
      };
    }
    sendJson(response, result.status, result.body);
  }

  /** Verifies and admits one raw signed webhook; exposed for deterministic tests and adapters. */
  async receiveWebhook(input: {
    body: Buffer;
    signature?: string;
    deliveryId?: string;
    event?: string;
  }): Promise<{ status: number; body: Record<string, unknown> }> {
    if (input.body.byteLength > this.maxBodyBytes)
      return {
        status: 413,
        body: { accepted: false, reason: 'body-too-large' }
      };
    if (!verifySignature(this.secret, input.body, input.signature))
      return {
        status: 401,
        body: { accepted: false, reason: 'signature-invalid' }
      };
    const { deliveryId, event } = input;
    if (
      !deliveryId ||
      !DELIVERY_ID.test(deliveryId) ||
      !event ||
      event.length > 64
    )
      return {
        status: 400,
        body: { accepted: false, reason: 'headers-invalid' }
      };
    let payload: unknown;
    try {
      payload = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(input.body)
      );
    } catch {
      return {
        status: 400,
        body: { accepted: false, reason: 'payload-invalid' }
      };
    }
    if (!isRecord(payload))
      return {
        status: 400,
        body: { accepted: false, reason: 'payload-invalid' }
      };
    this.pruneDeliveries();
    if (this.deliveries.has(deliveryId))
      return { status: 202, body: { accepted: true, duplicate: true } };
    const work = workFromEvent(event, payload, deliveryId);
    if (!work)
      return {
        status: 400,
        body: { accepted: false, reason: 'event-invalid' }
      };
    try {
      await this.refreshPersistentState();
    } catch {
      return {
        status: 503,
        body: { accepted: false, reason: 'delivery-state-unavailable' }
      };
    }
    if (work === 'installation-suspended') {
      const id = installationId(payload);
      if (id !== undefined) {
        this.pendingSuspensions.add(id);
        this.suspendedInstallations.add(id);
        if (
          !(await this.claimPersistentDelivery(deliveryId, {
            id,
            suspended: true
          }))
        )
          return { status: 202, body: { accepted: true, duplicate: true } };
        this.pendingSuspensions.delete(id);
        this.stopInstallationWork(id);
        this.rememberDelivery(deliveryId, 'complete');
        await this.writeAudit({
          event: 'installation-suspended',
          installationId: id,
          deliveryId
        });
      }
      return { status: 202, body: { accepted: true } };
    }
    if (work === 'installation-active') {
      const id = installationId(payload);
      if (id !== undefined) {
        if (
          !(await this.claimPersistentDelivery(deliveryId, {
            id,
            suspended: false
          }))
        )
          return { status: 202, body: { accepted: true, duplicate: true } };
        this.pendingSuspensions.delete(id);
        this.suspendedInstallations.delete(id);
        this.rememberDelivery(deliveryId, 'complete');
        await this.writeAudit({
          event: 'installation-active',
          installationId: id,
          deliveryId
        });
      }
      return { status: 202, body: { accepted: true } };
    }
    if (work === 'ignored') {
      if (!(await this.claimPersistentDelivery(deliveryId)))
        return { status: 202, body: { accepted: true, duplicate: true } };
      this.rememberDelivery(deliveryId, 'complete');
      return { status: 202, body: { accepted: true, ignored: true } };
    }
    const repository = this.repositories.get(work.repository);
    if (
      !repository ||
      repository.installationId !== work.installationId ||
      repository.repositoryId !== work.repositoryId
    ) {
      if (!(await this.claimPersistentDelivery(deliveryId)))
        return { status: 202, body: { accepted: true, duplicate: true } };
      this.rememberDelivery(deliveryId, 'complete');
      await this.writeAudit({
        event: 'repository-not-allowlisted',
        repository: work.repository,
        deliveryId
      });
      return { status: 202, body: { accepted: true, ignored: true } };
    }
    if (this.suspendedInstallations.has(work.installationId)) {
      if (!(await this.claimPersistentDelivery(deliveryId)))
        return { status: 202, body: { accepted: true, duplicate: true } };
      this.rememberDelivery(deliveryId, 'complete');
      await this.writeAudit({
        event: 'installation-suspended-delivery-ignored',
        installationId: work.installationId,
        repository: work.repository,
        deliveryId
      });
      return { status: 202, body: { accepted: true, ignored: true } };
    }
    if (this.closed)
      return {
        status: 503,
        body: { accepted: false, reason: 'service-closed' }
      };
    if (this.queue.length >= this.queueLimit)
      return {
        status: 503,
        body: { accepted: false, reason: 'scan-queue-full' }
      };
    if (!(await this.claimPersistentDelivery(deliveryId)))
      return { status: 202, body: { accepted: true, duplicate: true } };
    this.rememberDelivery(deliveryId, 'pending');
    this.queue.push({ work: Object.freeze(work), repository });
    await this.writeAudit({
      event: 'scan-queued',
      kind: work.kind,
      repository: work.repository,
      revision: work.revision,
      deliveryId
    });
    this.pump();
    return { status: 202, body: { accepted: true } };
  }

  private pump(): void {
    while (
      !this.closed &&
      this.active < this.concurrency &&
      this.queue.length > 0
    ) {
      const item = this.queue.shift();
      if (!item) return;
      this.active++;
      const controller = new AbortController();
      this.activeControllers.add(controller);
      this.controllerInstallations.set(controller, item.work.installationId);
      const deadline = setTimeout(
        () => controller.abort(new Error('scan-timeout')),
        this.scanTimeoutMs
      );
      void Promise.resolve()
        .then(() =>
          settleOnAbort(
            Promise.resolve().then(() =>
              this.options.scan(item.work, item.repository, controller.signal)
            ),
            controller.signal,
            { status: 'incomplete', findingCount: 0 }
          )
        )
        .then(async (summary) => {
          clearTimeout(deadline);
          const safeStatus = controller.signal.aborted
            ? 'incomplete'
            : ['complete', 'incomplete', 'failed'].includes(summary.status)
              ? summary.status
              : 'failed';
          const safeReason =
            !controller.signal.aborted &&
            typeof summary.reason === 'string' &&
            /^[a-z0-9][a-z0-9-]{0,63}$/u.test(summary.reason)
              ? summary.reason
              : controller.signal.aborted
                ? 'scan-cancelled-or-timed-out'
                : undefined;
          const safeSummary = Object.freeze({
            status: safeStatus as GitHubAppScanSummary['status'],
            findingCount:
              Number.isSafeInteger(summary.findingCount) &&
              summary.findingCount >= 0
                ? Math.min(summary.findingCount, 1_000_000)
                : 0,
            annotations: normalizeAnnotations(summary.annotations),
            ...(typeof summary.snapshotId === 'string' &&
            /^[a-f0-9]{64}$/iu.test(summary.snapshotId)
              ? { snapshotId: summary.snapshotId.toLowerCase() }
              : {}),
            ...(summary.revision && SHA.test(summary.revision)
              ? { revision: summary.revision.toLowerCase() }
              : {}),
            ...(safeReason ? { reason: safeReason } : {})
          });
          if (this.options.publishResult && !controller.signal.aborted) {
            try {
              await this.options.publishResult(
                item.work,
                item.repository,
                safeSummary,
                controller.signal
              );
              await this.writeAudit({
                event: 'check-run-published',
                repository: item.work.repository,
                revision: safeSummary.revision ?? item.work.revision,
                deliveryId: item.work.deliveryId
              });
            } catch {
              await this.writeAudit({
                event: 'check-run-publication-failed',
                reason: 'github-api-unavailable',
                repository: item.work.repository,
                revision: safeSummary.revision ?? item.work.revision,
                deliveryId: item.work.deliveryId
              });
            }
          }
          await this.writeAudit({
            event: 'scan-finished',
            status: safeStatus,
            findingCount: safeSummary.findingCount,
            snapshotId: safeSummary.snapshotId,
            ...(safeSummary.reason ? { reason: safeSummary.reason } : {}),
            repository: item.work.repository,
            revision: safeSummary.revision ?? item.work.revision,
            deliveryId: item.work.deliveryId
          });
        })
        .catch(async () => {
          await this.writeAudit({
            event: 'scan-failed',
            status: 'failed',
            reason: 'scanner-error',
            repository: item.work.repository,
            revision: item.work.revision,
            deliveryId: item.work.deliveryId
          });
        })
        .finally(() => {
          clearTimeout(deadline);
          if (item.work.kind === 'scheduled')
            this.scheduledRepositories.delete(item.work.repository);
          this.activeControllers.delete(controller);
          this.controllerInstallations.delete(controller);
          this.rememberDelivery(item.work.deliveryId, 'complete');
          this.active--;
          this.pump();
        });
    }
  }

  private rememberDelivery(id: string, state: DeliveryRecord['state']): void {
    const now = Date.now();
    this.deliveries.delete(id);
    this.deliveries.set(id, { state, expiresAt: now + this.dedupeTtlMs });
    this.pruneDeliveries();
  }

  private async refreshPersistentState(): Promise<void> {
    if (!this.journal) return;
    const snapshot = await this.journal.snapshot();
    this.suspendedInstallations.clear();
    for (const id of snapshot.suspendedInstallations)
      this.suspendedInstallations.add(id);
    for (const id of this.pendingSuspensions)
      this.suspendedInstallations.add(id);
  }

  private stopInstallationWork(installationId: number): void {
    for (let index = this.queue.length - 1; index >= 0; index--) {
      const item = this.queue[index];
      if (!item || item.work.installationId !== installationId) continue;
      this.queue.splice(index, 1);
      if (item.work.kind === 'scheduled')
        this.scheduledRepositories.delete(item.work.repository);
      this.rememberDelivery(item.work.deliveryId, 'complete');
      void this.writeAudit({
        event: 'scan-cancelled',
        reason: 'installation-suspended',
        repository: item.work.repository,
        deliveryId: item.work.deliveryId
      });
    }
    for (const [controller, owner] of this.controllerInstallations)
      if (owner === installationId)
        controller.abort(new Error('github-app-installation-suspended'));
  }

  private async claimPersistentDelivery(
    deliveryId: string,
    installation?: { id: number; suspended: boolean }
  ): Promise<boolean> {
    if (!this.journal) return true;
    return this.journal.claim(deliveryId, {
      now: Date.now(),
      ttlMs: this.dedupeTtlMs,
      limit: this.dedupeLimit,
      ...(installation ? { installation } : {})
    });
  }

  private pruneDeliveries(): void {
    const now = Date.now();
    for (const [id, record] of this.deliveries) {
      if (record.state === 'complete' && record.expiresAt <= now)
        this.deliveries.delete(id);
    }
    while (this.deliveries.size > this.dedupeLimit) {
      const oldest = this.deliveries.entries().next().value as
        [string, DeliveryRecord] | undefined;
      if (!oldest || oldest[1].state === 'pending') break;
      this.deliveries.delete(oldest[0]);
    }
  }

  private async writeAudit(
    entry: Readonly<Record<string, unknown>>
  ): Promise<void> {
    try {
      await this.audit(
        Object.freeze({ at: new Date().toISOString(), ...entry })
      );
    } catch {
      // Audit sink errors never expose webhook details or turn a queued scan
      // into a false clean result; the scan summary still records its state.
    }
  }
}

/** Shared scanner integration; only an exact, clean local Git revision is scanned. */
export function createGitHubAppScorecardScanner(
  options: {
    offline?: boolean;
    timeoutMs?: number;
    /** Snapshot factory seam for adversarial capture-race tests. */
    snapshotter?: typeof createProjectSnapshot;
    /** Scorecard runner seam for adversarial analysis-race tests. */
    scorecardRunner?: typeof buildSecurityScorecard;
  } = {}
): GitHubAppWebhookOptions['scan'] {
  const offline = options.offline ?? true;
  const timeoutMs = options.timeoutMs ?? 120_000;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1_000 ||
    timeoutMs > 600_000
  )
    throw new RangeError(
      'GitHub App scan timeout must be between 1000 and 600000.'
    );
  return async (work, repository, signal) => {
    try {
      const root = await realpath(path.resolve(repository.root));
      const [head, status] = await Promise.all([
        runGit(['rev-parse', '--verify', 'HEAD^{commit}'], {
          cwd: root,
          timeoutMs: 5_000,
          maxBuffer: 4_096
        }),
        runGit(['status', '--porcelain=v1', '--untracked-files=all'], {
          cwd: root,
          timeoutMs: 5_000,
          maxBuffer: 1_048_576
        })
      ]);
      const revision = head.stdout.toString('utf8').trim().toLowerCase();
      if (head.code !== 0 || !COMMIT_SHA.test(revision))
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: 'repository-revision-unavailable'
        };
      if (status.code !== 0 || status.stdout.byteLength !== 0)
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: 'repository-worktree-not-clean'
        };
      if (work.revision && work.revision !== revision)
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: 'requested-revision-not-provisioned'
        };
      if (signal.aborted)
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: 'scan-cancelled'
        };
      const snapshot = await (options.snapshotter ?? createProjectSnapshot)(
        root,
        { signal }
      );
      const [capturedHead, capturedStatus] = await Promise.all([
        runGit(['rev-parse', '--verify', 'HEAD^{commit}'], {
          cwd: root,
          signal,
          timeoutMs: 5_000,
          maxBuffer: 4_096
        }),
        runGit(['status', '--porcelain=v1', '--untracked-files=all'], {
          cwd: root,
          signal,
          timeoutMs: 5_000,
          maxBuffer: 1_048_576
        })
      ]);
      if (
        capturedHead.code !== 0 ||
        capturedStatus.code !== 0 ||
        capturedHead.stdout.toString('utf8').trim().toLowerCase() !==
          revision ||
        capturedStatus.stdout.byteLength !== 0
      )
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: 'repository-changed-during-snapshot'
        };
      if (
        snapshot.root !== root ||
        snapshot.gitHeadRevision !== revision ||
        snapshot.gitIndexStatus !== 'available' ||
        !snapshot.gitIndexDigest
      )
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: 'repository-snapshot-identity-unavailable'
        };
      const exactSnapshot = await verifySnapshotMatchesCommit(
        root,
        revision,
        snapshot,
        signal
      );
      if (!exactSnapshot.matches)
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: exactSnapshot.reason
        };
      const scorecard = await (
        options.scorecardRunner ?? buildSecurityScorecard
      )(
        root,
        {},
        {
          projectSnapshot: snapshot,
          offline,
          budget: { totalMs: timeoutMs, signal }
        }
      );
      const [analysisHead, analysisStatus, snapshotStillValid] =
        await Promise.all([
          runGit(['rev-parse', '--verify', 'HEAD^{commit}'], {
            cwd: root,
            signal,
            timeoutMs: 5_000,
            maxBuffer: 4_096
          }),
          runGit(['status', '--porcelain=v1', '--untracked-files=all'], {
            cwd: root,
            signal,
            timeoutMs: 5_000,
            maxBuffer: 1_048_576
          }),
          verifyProjectSnapshot(snapshot, { signal })
        ]);
      if (
        analysisHead.code !== 0 ||
        analysisStatus.code !== 0 ||
        analysisHead.stdout.toString('utf8').trim().toLowerCase() !==
          revision ||
        analysisStatus.stdout.byteLength !== 0 ||
        !snapshotStillValid
      )
        return {
          status: 'incomplete',
          findingCount: 0,
          reason: 'repository-changed-during-analysis'
        };
      return {
        status:
          scorecard.analysis.state === 'complete'
            ? 'complete'
            : scorecard.analysis.state === 'failed'
              ? 'failed'
              : 'incomplete',
        findingCount: scorecard.findings.length,
        annotations: normalizeAnnotations(
          scorecard.findings.flatMap((finding) => {
            const filePath = safeAnnotationPath(finding.location?.file);
            const line = finding.location?.line;
            if (
              !filePath ||
              !Number.isSafeInteger(line) ||
              (line as number) < 1 ||
              (line as number) > 2_147_483_647 ||
              !/^[A-Za-z0-9_.:-]{1,128}$/u.test(finding.ruleId) ||
              redactSensitiveText(finding.ruleId) !== finding.ruleId
            )
              return [];
            return [
              {
                path: filePath,
                line: line as number,
                severity: finding.severity,
                ruleId: finding.ruleId
              }
            ];
          })
        ),
        snapshotId: scorecard.snapshotId,
        revision,
        ...(scorecard.analysis.state !== 'complete'
          ? { reason: 'scorecard-incomplete' }
          : {})
      };
    } catch {
      return {
        status: 'failed',
        findingCount: 0,
        reason: 'scan-input-or-analysis-failed'
      };
    }
  };
}
