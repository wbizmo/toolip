import type { Command } from 'commander';
import chalk from 'chalk';
import { createScannerContext } from '../core/scanner-context.js';
import { printScannerContext } from '../utils/output.js';

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan project dependencies and security hygiene indicators.')
    .option('-p, --path <path>', 'Project path to scan.', process.cwd())
    .action(async (options: { path: string }) => {
      console.log(chalk.bold('Toolip Scan'));
      console.log('');

      const context = await createScannerContext(options.path);
      printScannerContext(context);

      console.log('');
      console.log(chalk.yellow('Supply chain analysis arrives in Sprint 2.'));
    });
}
