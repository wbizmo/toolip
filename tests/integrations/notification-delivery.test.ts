import { describe, expect, it, vi } from 'vitest';
import {
  deliverAlert,
  MemoryDeliveryLedger,
  type AlertEvent,
  type AlertDestination,
  type AlertTransport
} from '../../src/integrations/notifications/delivery.js';

const event: AlertEvent = {
  id: 'critical-001',
  kind: 'critical-introduced',
  findingCount: 2,
  createdAt: '2026-11-17T00:00:00.000Z',
  reportUrl: 'https://reports.example.test/signed/abc'
};
const destination: AlertDestination = {
  id: 'oncall',
  provider: 'slack',
  endpoint: 'https://hooks.slack.com/services/T00/B00/example',
  enabled: true,
  maximumAttempts: 1
};

describe('opt-in notification delivery boundaries', () => {
  it('never sends a disabled destination or duplicates a delivered event', async () => {
    const ledger = new MemoryDeliveryLedger();
    const transport: AlertTransport = { send: vi.fn(async () => ({ status: 200 })) };
    expect((await deliverAlert(event, { ...destination, enabled: false }, {
      ledger, transport
    })).state).toBe('disabled');
    expect((await deliverAlert(event, destination, { ledger, transport })).state).toBe('sent');
    expect((await deliverAlert(event, destination, { ledger, transport })).state).toBe('duplicate');
    expect(transport.send).toHaveBeenCalledTimes(1);
  });

  it('forbids arbitrary, local, and non-HTTPS receiver hosts', async () => {
    const ledger = new MemoryDeliveryLedger();
    const transport: AlertTransport = { send: vi.fn(async () => ({ status: 200 })) };
    for (const endpoint of [
      'http://hooks.slack.com/services/test',
      'https://127.0.0.1:443/test',
      'https://evil.example.test/not-a-slack-webhook',
      'https://user:pass@hooks.slack.com/services/test'
    ]) {
      await expect(deliverAlert(event, { ...destination, endpoint }, {
        ledger, transport
      })).rejects.toThrow();
    }
    expect(transport.send).not.toHaveBeenCalled();
  });

  it('sends fixed-size metadata but never report links without explicit consent', async () => {
    const payloads: string[] = [];
    const transport: AlertTransport = {
      send: vi.fn(async (_url, _headers, body) => {
        payloads.push(body);
        return { status: 201 };
      })
    };
    const result = await deliverAlert(event, destination, {
      ledger: new MemoryDeliveryLedger(), transport
    });
    expect(result.state).toBe('sent');
    expect(payloads).toHaveLength(1);
    expect(payloads[0]).toContain('critical-introduced');
    expect(payloads[0]).not.toContain('reports.example.test');
  });

  it('requires HMAC and exact operator host approval for generic webhooks', async () => {
    const outbound: Array<{ body: string; headers: Readonly<Record<string, string>> }> = [];
    const transport: AlertTransport = {
      send: vi.fn(async (_url, headers, body) => {
        outbound.push({ body, headers });
        return { status: 204 };
      })
    };
    const target: AlertDestination = {
      id: 'generic-one',
      provider: 'generic',
      enabled: true,
      endpoint: 'https://collector.example.test/webhook',
      allowedHosts: ['collector.example.test'],
      signingKey: 'a-long-separately-administered-signature-key-123'
    };
    expect((await deliverAlert(event, target, {
      ledger: new MemoryDeliveryLedger(), transport
    })).state).toBe('sent');
    expect(outbound[0]?.headers['X-Toolip-Signature']).toMatch(/^sha256=[a-f0-9]{64}$/u);
    expect(outbound[0]?.body).not.toContain(event.reportUrl);
    expect(outbound[0]?.body).toContain('toolip.dev/notification/v1');
  });

  it('releases failure claims to allow a later retry without false delivery', async () => {
    const ledger = new MemoryDeliveryLedger();
    let calls = 0;
    const transport: AlertTransport = {
      send: async () => ({ status: ++calls === 1 ? 400 : 204 })
    };
    const rejected = await deliverAlert(event, destination, { ledger, transport });
    const retried = await deliverAlert(event, destination, { ledger, transport });
    expect(rejected.state).toBe('failed');
    expect(retried.state).toBe('sent');
  });
});
