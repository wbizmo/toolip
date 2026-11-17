import path from 'node:path';
import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { readReport } from './report.js';
import {
  deliverAlert,
  fetchAlertTransport,
  type AlertDestination,
  type AlertKind,
  type AlertEvent
} from '../integrations/notifications/delivery.js';
import { FileDeliveryLedger } from '../integrations/notifications/file-ledger.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const kinds = new Set<AlertKind>([
  'critical-introduced',
  'kev-update',
  'incomplete-scan',
  'sla-breach',
  'release-status'
]);
type NotifyOptions = {
  kind: AlertKind;
  eventId: string;
  destinationId: string;
  provider: 'slack' | 'teams' | 'generic';
  allowedHost?: string;
  ledgerDir: string;
  enableNetwork?: boolean;
  sendReportLink?: boolean;
};

export function registerNotifyCommand(program: Command): void {
  program
    .command('notify')
    .description('Operator-triggered redacted notifications; network disabled by default.')
    .command('send <report>')
    .description('Send only bounded status metadata to an explicit destination.')
    .requiredOption('--kind <kind>', 'Named status event kind.')
    .requiredOption('--event-id <id>', 'Stable idempotency identity for this event.')
    .requiredOption('--destination-id <id>', 'Stable operator destination identity.')
    .requiredOption('--provider <provider>', 'slack, teams or generic.')
    .requiredOption('--ledger-dir <absolute>', 'Private durable delivery ledger, outside the scanned project.')
    .option('--allowed-host <host>', 'Exact operator-approved host for Teams or generic provider.')
    .option('--enable-network', 'Explicit consent to send a webhook.')
    .option('--send-report-link', 'Explicit consent to include TOOLIP_ALERT_REPORT_URL.')
    .action(async (file: string, options: NotifyOptions) => {
      if (!options.enableNetwork)
        throw new ToolipError('Notification delivery requires --enable-network.', {
          code: 'NOTIFICATION_NETWORK_CONSENT_REQUIRED',
          exitCode: 1
        });
      if (!kinds.has(options.kind) || !idPattern.test(options.eventId) ||
          !idPattern.test(options.destinationId) ||
          !['slack', 'teams', 'generic'].includes(options.provider))
        throw new ToolipError('Notification kind or identity is invalid.', {
          code: 'NOTIFICATION_INPUT_INVALID',
          exitCode: 1
        });
      const workspace = path.resolve(process.cwd());
      const ledger = path.resolve(options.ledgerDir);
      if (
        !path.isAbsolute(options.ledgerDir) ||
        ledger === workspace ||
        ledger.startsWith(workspace + path.sep)
      )
        throw new ToolipError(
          'Notification ledger must be an absolute private directory outside the scanned workspace.',
          { code: 'NOTIFICATION_LEDGER_INVALID', exitCode: 1 }
        );
      // Webhook endpoint and HMAC secret are never accepted as argv values,
      // interpolated into messages, or read from the untrusted scanned repo.
      const endpoint = process.env.TOOLIP_ALERT_WEBHOOK_URL;
      if (!endpoint)
        throw new ToolipError('TOOLIP_ALERT_WEBHOOK_URL is not configured.', {
          code: 'NOTIFICATION_ENDPOINT_MISSING', exitCode: 1
        });
      if (options.provider !== 'slack' && !options.allowedHost)
        throw new ToolipError('An exact --allowed-host is required.', {
          code: 'NOTIFICATION_HOST_APPROVAL_REQUIRED', exitCode: 1
        });
      if (
        options.sendReportLink &&
        !process.env.TOOLIP_ALERT_REPORT_URL
      )
        throw new ToolipError(
          'Explicit report-link delivery requires TOOLIP_ALERT_REPORT_URL.',
          { code: 'NOTIFICATION_REPORT_LINK_MISSING', exitCode: 1 }
        );
      const report = await readReport(file);
      if (options.kind === 'critical-introduced' &&
          report.summary.critical <= 0)
        throw new ToolipError('Report contains no critical findings for this event.', {
          code: 'NOTIFICATION_EVENT_MISMATCH', exitCode: 1
        });
      if (options.kind === 'incomplete-scan' &&
          report.analysis?.state === 'complete')
        throw new ToolipError('Report is complete; incomplete-scan event denied.', {
          code: 'NOTIFICATION_EVENT_MISMATCH', exitCode: 1
        });
      const event: AlertEvent = {
        id: options.eventId,
        kind: options.kind,
        findingCount: report.summary.totalFindings,
        createdAt: new Date().toISOString(),
        ...(options.sendReportLink
          ? { reportUrl: process.env.TOOLIP_ALERT_REPORT_URL }
          : {})
      };
      const destination: AlertDestination = {
        id: options.destinationId,
        provider: options.provider,
        endpoint,
        enabled: true,
        allowedHosts: options.allowedHost ? [options.allowedHost] : [],
        signingKey: options.provider === 'generic'
          ? process.env.TOOLIP_ALERT_SIGNING_KEY
          : undefined,
        sendReportLink: options.sendReportLink === true,
        maximumAttempts: 3,
        timeoutMs: 5_000
      };
      const result = await deliverAlert(event, destination, {
        ledger: new FileDeliveryLedger(options.ledgerDir),
        transport: fetchAlertTransport()
      });
      console.log(serializeJsonOutputBounded({
        ...result,
        reportAnalysisState: report.analysis?.state ?? 'unknown',
        complete: report.analysis?.state === 'complete'
      }));
      if (result.state === 'failed') process.exitCode = 3;
    });
}
