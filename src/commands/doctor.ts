import type { Command } from 'commander';
import chalk from 'chalk';
import { createScannerContext } from '../core/scanner-context.js';
import { printScannerContext } from '../utils/output.js';

export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Run a full project security hygiene audit.')
    .option('-p, --path <path>', 'Project path to audit.', process.cwd())
    .action(async (options: { path: string }) => {
      console.log(chalk.bold('Toolip Doctor'));
      console.log('');

      const context = await createScannerContext(options.path);
      printScannerContext(context);

      console.log('');
      console.log(chalk.yellow('Security checks arrive in Sprint 3.'));
    });
}
