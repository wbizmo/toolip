import type { Command } from 'commander';
import chalk from 'chalk';
import { installPreCommitHook } from '../core/hooks.js';

export function registerHookCommand(program: Command): void {
  const hook = program
    .command('hook')
    .description('Install Toolip Git hooks.');

  hook
    .command('install')
    .description('Install Toolip pre-commit hook.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .action(async (options: { path: string }) => {
      const hookPath = await installPreCommitHook(options.path);
      console.log(`${chalk.green('✓')} Installed pre-commit hook at ${hookPath}`);
    });
}
