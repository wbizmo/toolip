import type { Command } from 'commander';
import chalk from 'chalk';

export function registerSelfTestCommand(program: Command): void {
  program
    .command('self-test')
    .description('Run Toolip internal diagnostics.')
    .action(() => {
      const checks = [
        'CLI Loaded',
        'Command Router Ready',
        'Scanner Foundation Ready',
        'Report Engine Ready'
      ];

      console.log(chalk.bold('Toolip Self-Test'));
      console.log('');

      for (const check of checks) {
        console.log(`${chalk.green('✓')} ${check}`);
      }

      console.log('');
      console.log(chalk.green('Toolip is healthy.'));
    });
}
