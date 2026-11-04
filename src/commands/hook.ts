import type { Command } from 'commander';
import chalk from 'chalk';
import { installPreCommitHookDetailed } from '../core/hooks.js';

export function registerHookCommand(program: Command): void {
  const hook = program.command('hook').description('Install Toolip Git hooks.');

  hook
    .command('install')
    .description('Install Toolip pre-commit hook.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .action(async (options: { path: string }) => {
      const result = await installPreCommitHookDetailed(options.path);
      console.log(
        `${chalk.green('✓')} Installed pre-commit hook at ${result.hookPath}`
      );
      for (const warning of result.warnings) {
        console.log(`${chalk.yellow('!')} ${warning}`);
      }
    });
}
