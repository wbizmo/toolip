import type { Command } from 'commander';
import {
  clearHistory,
  protectHistoryIntegrity,
  readHistory,
  rotateHistoryIntegrityKey
} from '../core/history/store.js';
import type { HistoryIntegrityOptions } from '../core/history/store.js';
import {
  compareHistoryEntries,
  remediationSla
} from '../core/history/baseline.js';
import {
  renderHistoryDelta,
  type HistoryDeltaFormat
} from '../core/history/report.js';
import { readHmacKeyFile } from '../core/secure-key-file.js';

type HistoryOptions = {
  path: string;
  json?: boolean;
  limit: string;
  integrityKey?: string;
};

export function registerHistoryCommand(program: Command): void {
  const command = program
    .command('history')
    .description('Inspect locally stored Toolip scan history.');

  command
    .command('list')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option('-l, --limit <number>', 'Maximum entries.', '20')
    .option('--integrity-key <file>', 'Verify authenticated local history.')
    .option('--json', 'Print JSON.')
    .action(async (options: HistoryOptions) => {
      const history = await readHistory(
        options.path,
        await loadHistoryKey(options.integrityKey)
      );
      reportUnsignedHistory(history.integrity !== undefined);
      const limit = Math.max(1, Number.parseInt(options.limit, 10) || 20);

      const entries = history.entries.slice(-limit);

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              schemaVersion: history.schemaVersion,
              integrityStatus: history.integrity ? 'verified' : 'unsigned',
              entries
            },
            null,
            2
          )
        );
        return;
      }

      console.log('Toolip History');
      console.log('');

      if (entries.length === 0) {
        console.log('No historical scan entries are available.');
        return;
      }

      for (const entry of entries.reverse()) {
        console.log(
          `${entry.createdAt} ${entry.command} ` +
            `score=${entry.score ?? 'n/a'} ` +
            `findings=${entry.summary.total}`
        );

        if (entry.git?.branch || entry.git?.commit) {
          console.log(
            `  ${entry.git.branch ?? 'detached'} ` +
              `${entry.git.commit?.slice(0, 12) ?? ''}`
          );
        }
      }
    });

  command
    .command('trend')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option('-l, --limit <number>', 'Maximum entries.', '10')
    .option('--integrity-key <file>', 'Verify authenticated local history.')
    .action(async (options: HistoryOptions) => {
      const history = await readHistory(
        options.path,
        await loadHistoryKey(options.integrityKey)
      );
      reportUnsignedHistory(history.integrity !== undefined);
      const limit = Math.max(2, Number.parseInt(options.limit, 10) || 10);

      const entries = history.entries
        .filter((entry) => entry.score !== undefined)
        .slice(-limit);

      console.log('Toolip Security Trend');
      console.log('');

      if (entries.length < 2) {
        console.log('At least two scored history entries are required.');
        return;
      }

      const first = entries[0];
      const last = entries[entries.length - 1];

      console.log(`Score: ${first?.score} → ${last?.score}`);
      console.log(`Change: ${(last?.score ?? 0) - (first?.score ?? 0)}`);
      console.log(`Findings: ${first?.summary.total} → ${last?.summary.total}`);
    });

  command
    .command('diff')
    .description('Compare the latest scan with a complete historical baseline.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option(
      '--base <entry-id>',
      'Baseline history entry ID; defaults to previous scan.'
    )
    .option('--json', 'Print the fingerprint delta as JSON.')
    .option('--integrity-key <file>', 'Verify authenticated local history.')
    .option(
      '--format <format>',
      'Output json, markdown, html or sarif.',
      'json'
    )
    .action(
      async (options: {
        path: string;
        base?: string;
        json?: boolean;
        format?: string;
        integrityKey?: string;
      }) => {
        const history = await readHistory(
          options.path,
          await loadHistoryKey(options.integrityKey)
        );
        reportUnsignedHistory(history.integrity !== undefined);
        const current = history.entries.at(-1);
        if (!current) {
          console.log('No scan history is available.');
          return;
        }
        const baseline = options.base
          ? history.entries.find((entry) => entry.id === options.base)
          : history.entries.at(-2);
        if (!baseline) {
          throw new Error(
            options.base
              ? 'Requested history baseline was not found.'
              : 'At least two history entries are required for a baseline comparison.'
          );
        }
        const delta = history.integrity
          ? compareHistoryEntries(current, baseline)
          : {
              new: [],
              fixed: [],
              unchanged: [],
              unknown: [
                ...new Set([
                  ...(current.findingFingerprints ?? []),
                  ...(baseline.findingFingerprints ?? [])
                ])
              ].sort(),
              comparisonBase: baseline.id,
              coverageComparable: false
            };
        const format = options.json ? 'json' : (options.format ?? 'json');
        if (!['json', 'markdown', 'html', 'sarif'].includes(format)) {
          throw new Error(
            'History format must be json, markdown, html or sarif.'
          );
        }
        process.stdout.write(
          renderHistoryDelta({
            delta,
            current,
            baseline,
            format: format as HistoryDeltaFormat
          })
        );
      }
    );

  command
    .command('sla')
    .description('Report finding remediation deadlines from local history.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option('--critical-days <days>', 'Critical finding remediation SLA.', '1')
    .option('--high-days <days>', 'High finding remediation SLA.', '7')
    .option('--medium-days <days>', 'Medium finding remediation SLA.', '30')
    .option('--low-days <days>', 'Low finding remediation SLA.', '90')
    .option(
      '--info-days <days>',
      'Informational finding remediation SLA.',
      '180'
    )
    .option('--json', 'Print JSON.')
    .option('--integrity-key <file>', 'Verify authenticated local history.')
    .action(
      async (options: {
        path: string;
        criticalDays: string;
        highDays: string;
        mediumDays: string;
        lowDays: string;
        infoDays: string;
        json?: boolean;
        integrityKey?: string;
      }) => {
        const history = await readHistory(
          options.path,
          await loadHistoryKey(options.integrityKey)
        );
        reportUnsignedHistory(history.integrity !== undefined);
        const latest = history.entries.at(-1);
        if (!latest) {
          console.log('No scan history is available.');
          return;
        }
        const policy = {
          critical: parseSlaDays(options.criticalDays),
          high: parseSlaDays(options.highDays),
          medium: parseSlaDays(options.mediumDays),
          low: parseSlaDays(options.lowDays),
          info: parseSlaDays(options.infoDays)
        };
        const entries = remediationSla(latest, policy);
        if (options.json) {
          console.log(
            JSON.stringify(
              {
                coverage: latest.coverage,
                integrityStatus: history.integrity ? 'verified' : 'unsigned',
                entries,
                overdue: entries.filter((entry) => entry.overdue).length
              },
              null,
              2
            )
          );
          return;
        }
        console.log('Toolip Remediation SLA');
        console.log(`Open findings: ${entries.length}`);
        console.log(
          `Overdue: ${entries.filter((entry) => entry.overdue).length}`
        );
        if (latest.coverage?.state !== 'complete') {
          console.log(
            'Latest scan coverage is incomplete; this report does not imply unobserved findings were resolved.'
          );
        }
        for (const entry of entries) {
          console.log(
            `${entry.severity.toUpperCase()} ${entry.ruleId}: due ${entry.dueAt}${entry.overdue ? ' (overdue)' : ''}`
          );
        }
      }
    );

  command
    .command('protect')
    .description('Add an authenticated HMAC chain to legacy local history.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .requiredOption('--integrity-key <file>', 'Private 256-bit hex HMAC key.')
    .action(async (options: { path: string; integrityKey: string }) => {
      const key = await loadHistoryKey(options.integrityKey);
      if (!key) throw new Error('A history integrity key is required.');
      await protectHistoryIntegrity(options.path, key);
      console.log('Toolip history integrity protection enabled.');
    });

  command
    .command('rotate-key')
    .description('Rotate the HMAC key on an authenticated local history chain.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .requiredOption('--current-key <file>', 'Current private 256-bit hex key.')
    .requiredOption('--new-key <file>', 'New private 256-bit hex key.')
    .action(
      async (options: { path: string; currentKey: string; newKey: string }) => {
        const current = await loadHistoryKey(options.currentKey);
        const next = await loadHistoryKey(options.newKey);
        if (!current || !next)
          throw new Error(
            'Current and new history integrity keys are required.'
          );
        await rotateHistoryIntegrityKey(options.path, current, next);
        console.log('Toolip history integrity key rotated.');
      }
    );

  command
    .command('clear')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option(
      '--integrity-key <file>',
      'Verify and preserve authenticated history.'
    )
    .action(async (options: { path: string; integrityKey?: string }) => {
      await clearHistory(
        options.path,
        await loadHistoryKey(options.integrityKey)
      );
      console.log('Toolip history cleared.');
    });
}

async function loadHistoryKey(
  keyFile?: string
): Promise<HistoryIntegrityOptions | undefined> {
  return keyFile ? readHmacKeyFile(keyFile) : undefined;
}

function reportUnsignedHistory(authenticated: boolean): void {
  if (!authenticated)
    console.error(
      'Warning: local history is unsigned; this output is not an authenticated security timeline.'
    );
}

function parseSlaDays(value: string): number {
  const days = Number(value);
  if (!Number.isFinite(days) || days < 0 || days > 3650)
    throw new Error('SLA values must be between 0 and 3,650 days.');
  return days;
}
