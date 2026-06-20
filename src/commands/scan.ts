import type { Command } from 'commander';
import chalk from 'chalk';

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan project dependencies and security hygiene indicators.')
    .option('-p, --path <path>', 'Project path to scan.', process.cwd())
    .action((options: { path: string }) => {
      console.log(chalk.bold('Toolip Scan'));
      console.log('');
      console.log(`Project: ${options.path}`);
      console.log('');
      console.log(chalk.yellow('Sprint 1 scanner foundation is installed. Supply chain analysis arrives in Sprint 2.'));
    });
}
