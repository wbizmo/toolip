import type { Command } from 'commander';
import { generateAnnouncement } from '../core/announce/generate.js';

export function registerAnnounceCommand(program: Command): void {
  program
    .command('announce')
    .description('Generate a deterministic plain-language security update.')
    .option('--version <version>', 'Release version.')
    .option('--fixed <number>', 'Fixed findings.', '0')
    .option('--added <number>', 'New findings.', '0')
    .option('--removed <number>', 'Removed findings.', '0')
    .option('--score-before <number>', 'Previous score.')
    .option('--score-after <number>', 'Current score.')
    .action((options: Record<string, string | undefined>) => {
      console.log(
        generateAnnouncement({
          version: options.version,
          fixed: Number(options.fixed ?? 0),
          added: Number(options.added ?? 0),
          removed: Number(options.removed ?? 0),
          scoreBefore:
            options.scoreBefore === undefined
              ? undefined
              : Number(options.scoreBefore),
          scoreAfter:
            options.scoreAfter === undefined
              ? undefined
              : Number(options.scoreAfter)
        })
      );
    });
}
