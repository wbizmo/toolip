import { createHmac } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

export type AlertKind =
  | 'critical-introduced'
  | 'kev-update'
  | 'incomplete-scan'
  | 'sla-breach'
  | 'release-status';

export type AlertEvent = Readonly<{
  id: string;
  kind: AlertKind;
  findingCount: number;
  createdAt: string;
  /** Optional pre-approved report link; never transmitted by default. */
  reportUrl?: string;
}>;

export type AlertDestination = Readonly<{
  id: string;
  provider: 'slack' | 'teams' | 'generic';
  endpoint: string;
  enabled: boolean;
  allowedHosts?: readonly string[];
  /** A secret is required for generic signed webhook events. */
  signingKey?: string;
  sendReportLink?: boolean;
  timeoutMs?: number;
  maximumAttempts?: number;
}>;

export type AlertDeliveryResult = Readonly<{
  destinationId: string;
  eventId: string;
  state: 'sent' | 'duplicate' | 'disabled' | 'failed';
  attempts: number;
  reason?: string;
}>;

export interface DeliveryLedger {
  /** Atomically acquire a unique (destination,event) key. */
  claim(key: string): Promise<boolean>;
  /** Allow a later retry if this delivery did not succeed. */
  release(key: string): Promise<void>;
}

export interface AlertTransport {
  send(
    endpoint: URL,
    headers: Readonly<Record<string, string>>,
    body: string,
    timeoutMs: number,
    signal?: AbortSignal
  ): Promise<{ status: number; retryAfterSeconds?: number }>;
}

/**
 * In-memory ledger prevents duplicate sends within a process. Distributed
 * workers must provide a persistent, atomic ledger; in-memory state makes no
 * cross-process exactly-once guarantee.
 */
export class MemoryDeliveryLedger implements DeliveryLedger {
  private readonly keys = new Set<string>();
  constructor(private readonly maximumKeys = 10_000) {
    if (!Number.isSafeInteger(maximumKeys) || maximumKeys < 1 || maximumKeys > 100_000)
      throw new RangeError('Delivery ledger capacity is invalid.');
  }
  async claim(key: string): Promise<boolean> {
    if (this.keys.has(key)) return false;
    if (this.keys.size >= this.maximumKeys)
      throw new Error('Delivery ledger is full; delivery denied rather than silently forgetting prior keys.');
    this.keys.add(key);
    return true;
  }
  async release(key: string): Promise<void> {
    this.keys.delete(key);
  }
}

const acceptedKinds = new Set<AlertKind>([
  'critical-introduced', 'kev-update', 'incomplete-scan',
  'sla-breach', 'release-status'
]);
const validId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const validSha = /^[a-f0-9]{64}$/u;
const maxBodyBytes = 4096;
const defaultTimeoutMs = 5_000;
const maxRetries = 3;

function trustedEndpoint(target: AlertDestination): URL {
  const endpoint = new URL(target.endpoint);
  if (
    endpoint.protocol !== 'https:' ||
    endpoint.username || endpoint.password ||
    endpoint.hash ||
    endpoint.port !== '' ||
    endpoint.hostname.length > 253 ||
    endpoint.pathname.length > 1024
  )
    throw new Error('Notification endpoint must be a bounded credential-free HTTPS URL.');
  const host = endpoint.hostname.toLowerCase();
  const explicit = target.allowedHosts ?? [];
  if (explicit.length > 32 || explicit.some((item) =>
    !/^[a-z0-9.-]{1,253}$/u.test(item)
  ))
    throw new Error('Notification hostname allowlist is invalid.');
  if (target.provider === 'slack') {
    if (host !== 'hooks.slack.com')
      throw new Error('Slack notification endpoint is not trusted.');
  } else if (target.provider === 'teams') {
    // Modern Microsoft Teams workflow URLs use region-specific Logic Apps
    // domains. Require an explicit operator-owned exact host allowlist.
    if (!explicit.includes(host))
      throw new Error('Teams notification host is not operator-approved.');
  } else if (target.provider === 'generic') {
    if (!target.signingKey || Buffer.byteLength(target.signingKey, 'utf8') < 32)
      throw new Error('Generic webhook requires a configured HMAC signing key.');
    if (!explicit.includes(host))
      throw new Error('Generic notification host is not operator-approved.');
  } else {
    throw new Error('Unsupported notification provider.');
  }
  if (host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.local') || /^[0-9.]+$/u.test(host) ||
      host.includes(':'))
    throw new Error('IP-literal or local notification hosts are forbidden.');
  return endpoint;
}

function validateEvent(event: AlertEvent): void {
  if (!validId.test(event.id) || !acceptedKinds.has(event.kind) ||
      !Number.isSafeInteger(event.findingCount) || event.findingCount < 0 ||
      !Number.isFinite(Date.parse(event.createdAt)) ||
      event.createdAt !== new Date(Date.parse(event.createdAt)).toISOString())
    throw new TypeError('Notification event has invalid identity or metadata.');
  if (event.reportUrl !== undefined) {
    if (event.reportUrl.length > 1024) throw new Error('Report URL is too long.');
    const url = new URL(event.reportUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash)
      throw new Error('Report link must be credential-free HTTPS.');
  }
}

function payloadFor(event: AlertEvent, destination: AlertDestination): string {
  const summary = {
    schema: 'toolip.dev/notification/v1',
    eventId: event.id,
    kind: event.kind,
    findingCount: event.findingCount,
    occurredAt: event.createdAt,
    ...(destination.sendReportLink === true && event.reportUrl
      ? { reportUrl: event.reportUrl }
      : {})
  };
  const summaryJson = JSON.stringify(summary);
  // Never include scanned source snippets, private package names, file paths,
  // secret fingerprints, or full report contents in outbound notifications.
  if (Buffer.byteLength(summaryJson, 'utf8') > maxBodyBytes)
    throw new RangeError('Notification payload exceeds bounded limit.');
  if (destination.provider === 'slack')
    return JSON.stringify({ text: `Toolip: ${event.kind}; findings: ${event.findingCount}; event: ${event.id}` });
  if (destination.provider === 'teams')
    return JSON.stringify({ type: 'message', attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        type: 'AdaptiveCard', version: '1.4',
        body: [{ type: 'TextBlock', text: `Toolip: ${event.kind} (${event.findingCount} findings)` }]
      }
    }] });
  return summaryJson;
}

/** Explicitly opted-in delivery with bounded retries and no implicit egress. */
export async function deliverAlert(
  event: AlertEvent,
  destination: AlertDestination,
  dependencies: {
    ledger: DeliveryLedger;
    transport: AlertTransport;
    signal?: AbortSignal;
  }
): Promise<AlertDeliveryResult> {
  validateEvent(event);
  if (!validId.test(destination.id)) throw new TypeError('Invalid notification destination ID.');
  if (!destination.enabled) return {
    destinationId: destination.id, eventId: event.id, state: 'disabled', attempts: 0
  };
  if (dependencies.signal?.aborted) return {
    destinationId: destination.id, eventId: event.id, state: 'failed', attempts: 0,
    reason: 'cancelled'
  };
  const endpoint = trustedEndpoint(destination);
  const timeout = destination.timeoutMs ?? defaultTimeoutMs;
  const attemptsLimit = destination.maximumAttempts ?? maxRetries;
  if (!Number.isSafeInteger(timeout) || timeout < 100 || timeout > 10_000 ||
      !Number.isSafeInteger(attemptsLimit) || attemptsLimit < 1 ||
      attemptsLimit > maxRetries)
    throw new RangeError('Notification retry or timeout budget is invalid.');
  const key = createHmac('sha256', 'toolip-notification-ledger/v1')
    .update(destination.id).update('\0').update(event.id).digest('hex');
  if (!(await dependencies.ledger.claim(key)))
    return { destinationId: destination.id, eventId: event.id, state: 'duplicate', attempts: 0 };

  let successful = false;
  let attempts = 0;
  try {
    const body = payloadFor(event, destination);
    if (Buffer.byteLength(body, 'utf8') > maxBodyBytes)
      throw new RangeError('Notification payload exceeds bounded limit.');
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'toolip-notifications',
      'X-Toolip-Event-Id': event.id
    };
    if (destination.provider === 'generic') {
      const timestamp = new Date().toISOString();
      headers['X-Toolip-Timestamp'] = timestamp;
      headers['X-Toolip-Signature'] = 'sha256=' + createHmac(
        'sha256', destination.signingKey as string
      ).update(timestamp).update('\n').update(body).digest('hex');
    }
    for (let attempt = 1; attempt <= attemptsLimit; attempt += 1) {
      if (dependencies.signal?.aborted) break;
      attempts = attempt;
      try {
        const response = await dependencies.transport.send(
          endpoint, headers, body, timeout, dependencies.signal
        );
        if (response.status >= 200 && response.status < 300) {
          successful = true;
          return { destinationId: destination.id, eventId: event.id, state: 'sent', attempts };
        }
        if (response.status !== 429 && response.status < 500) break;
        if (attempt < attemptsLimit) {
          const backoff = Math.min(
            1_500,
            Math.max(200 * 2 ** (attempt - 1),
              Math.max(0, (response.retryAfterSeconds ?? 0) * 1000))
          );
          await sleep(backoff, undefined, { signal: dependencies.signal });
        }
      } catch {
        // Keep all remote error bodies, URLs and tokens out of results/logs.
        if (attempt < attemptsLimit && !dependencies.signal?.aborted)
          await sleep(Math.min(1_500, 200 * 2 ** (attempt - 1)), undefined, {
            signal: dependencies.signal
          }).catch(() => undefined);
      }
    }
    return {
      destinationId: destination.id, eventId: event.id, state: 'failed',
      attempts, reason: dependencies.signal?.aborted ? 'cancelled' : 'delivery-rejected'
    };
  } finally {
    if (!successful) await dependencies.ledger.release(key);
  }
}

/** Network transport is injectable so callers can enforce stronger egress isolation. */
export function fetchAlertTransport(fetcher: typeof fetch = fetch): AlertTransport {
  return {
    async send(endpoint, headers, body, timeoutMs, signal) {
      const abort = new AbortController();
      const onAbort = () => abort.abort(signal?.reason);
      signal?.addEventListener('abort', onAbort, { once: true });
      const timeout = setTimeout(() => abort.abort(), timeoutMs);
      try {
        const result = await fetcher(endpoint, {
          method: 'POST', redirect: 'error',
          headers, body, signal: abort.signal
        });
        // Never consume response bodies from untrusted remote endpoints.
        return {
          status: result.status,
          retryAfterSeconds: Math.min(
            2, Math.max(0, Number(result.headers.get('retry-after')) || 0)
          )
        };
      } finally {
        clearTimeout(timeout);
        signal?.removeEventListener('abort', onAbort);
      }
    }
  };
}
