import type { Command } from 'commander';
import {
  clearHistory,
  readHistory
} from '../core/history/store.js';

type HistoryOptions = {
  path: string;
  json?: boolean;
  limit: string;
};

export function registerHistoryCommand(
  program: Command
): void {
  const command = program
    .command('history')
    .description(
      'Inspect locally stored Toolip scan history.'
    );

  command
    .command('list')
    .option(
      '-p, --path <path>',
      'Project path.',
      process.cwd()
    )
    .option(
      '-l, --limit <number>',
      'Maximum entries.',
      '20'
    )
    .option('--json', 'Print JSON.')
    .action(async (options: HistoryOptions) => {
      const history = await readHistory(options.path);
      const limit = Math.max(
        1,
        Number.parseInt(options.limit, 10) || 20
      );

      const entries = history.entries.slice(-limit);

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              schemaVersion:
                history.schemaVersion,
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
        console.log(
          'No historical scan entries are available.'
        );
        return;
      }

      for (const entry of entries.reverse()) {
        console.log(
          `${entry.createdAt} ${entry.command} ` +
            `score=${entry.score ?? 'n/a'} ` +
            `findings=${entry.summary.total}`
        );

        if (
          entry.git?.branch ||
          entry.git?.commit
        ) {
          console.log(
            `  ${entry.git.branch ?? 'detached'} ` +
              `${entry.git.commit?.slice(0, 12) ?? ''}`
          );
        }
      }
    });

  command
    .command('trend')
    .option(
      '-p, --path <path>',
      'Project path.',
      process.cwd()
    )
    .option(
      '-l, --limit <number>',
      'Maximum entries.',
      '10'
    )
    .action(async (options: HistoryOptions) => {
      const history = await readHistory(options.path);
      const limit = Math.max(
        2,
        Number.parseInt(options.limit, 10) || 10
      );

      const entries = history.entries
        .filter(
          (entry) => entry.score !== undefined
        )
        .slice(-limit);

      console.log('Toolip Security Trend');
      console.log('');

      if (entries.length < 2) {
        console.log(
          'At least two scored history entries are required.'
        );
        return;
      }

      const first = entries[0];
      const last = entries[entries.length - 1];

      console.log(
        `Score: ${first?.score} → ${last?.score}`
      );
      console.log(
        `Change: ${(last?.score ?? 0) - (first?.score ?? 0)}`
      );
      console.log(
        `Findings: ${first?.summary.total} → ${last?.summary.total}`
      );
    });

  command
    .command('clear')
    .option(
      '-p, --path <path>',
      'Project path.',
      process.cwd()
    )
    .action(async (options: { path: string }) => {
      await clearHistory(options.path);
      console.log('Toolip history cleared.');
    });
}
