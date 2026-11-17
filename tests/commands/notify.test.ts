import { afterEach, describe, expect, it } from 'vitest';
import { createProgram } from '../../src/cli/program.js';

const originalWebhook = process.env.TOOLIP_ALERT_WEBHOOK_URL;
const originalReportUrl = process.env.TOOLIP_ALERT_REPORT_URL;

afterEach(() => {
  if (originalWebhook === undefined) delete process.env.TOOLIP_ALERT_WEBHOOK_URL;
  else process.env.TOOLIP_ALERT_WEBHOOK_URL = originalWebhook;
  if (originalReportUrl === undefined) delete process.env.TOOLIP_ALERT_REPORT_URL;
  else process.env.TOOLIP_ALERT_REPORT_URL = originalReportUrl;
});

const args = [
  'node', 'toolip',
  'notify', 'send', 'report-that-should-not-be-opened.json',
  '--kind', 'critical-introduced',
  '--event-id', 'event-001',
  '--destination-id', 'oncall',
  '--provider', 'slack',
  '--ledger-dir', '/tmp/toolip-uncreated-ledger'
];

describe('notification CLI fail-closed opt-in', () => {
  it('never reads a report or contacts an endpoint without network consent', async () => {
    process.env.TOOLIP_ALERT_WEBHOOK_URL =
      'https://hooks.slack.com/services/test/path';
    await expect(createProgram().parseAsync(args))
      .rejects.toThrow('requires --enable-network');
  });

  it('never opens a report or contacts a provider when the destination is absent', async () => {
    delete process.env.TOOLIP_ALERT_WEBHOOK_URL;
    await expect(createProgram().parseAsync([...args, '--enable-network']))
      .rejects.toThrow('not configured');
  });

  it('refuses optional report-link transmission when its source is missing', async () => {
    process.env.TOOLIP_ALERT_WEBHOOK_URL =
      'https://hooks.slack.com/services/test/path';
    delete process.env.TOOLIP_ALERT_REPORT_URL;
    await expect(createProgram().parseAsync([
      ...args, '--enable-network', '--send-report-link'
    ])).rejects.toThrow('requires TOOLIP_ALERT_REPORT_URL');
  });
});
