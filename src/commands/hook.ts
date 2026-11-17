import type { Command } from 'commander';
import chalk from 'chalk';
import { installPreCommitHookDetailed, uninstallPreCommitHookDetailed } from '../core/hooks.js';

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

  hook
    .command('setup')
    .description('Show safe native Git, Husky or lint-staged integration steps.')
    .option('--manager <name>', 'native, husky, or lint-staged.', 'native')
    .option('--apply', 'Explicitly authorize a non-destructive managed-hook change.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .action(async (options: {
      manager: string;
      apply?: boolean;
      path: string;
    }) => {
      if (!['native', 'husky', 'lint-staged'].includes(options.manager))
        throw new Error('Hook manager must be native, husky or lint-staged.');
      if (options.manager === 'lint-staged') {
        if (options.apply)
          throw new Error(
            'lint-staged integration needs manual approval of its configuration; Toolip will not modify package scripts.'
          );
        console.log('Add \"toolip pre-commit --path .\" as a separate, full-index Git hook alongside lint-staged.');
        console.log('Do not call it once per file: Toolip scans the actual staged Git index.');
        return;
      }
      if (!options.apply) {
        console.log(
          'No files changed. Run toolip hook setup --manager ' +
          options.manager + ' --apply to explicitly install the managed block.'
        );
        return;
      }
      const result = await installPreCommitHookDetailed(options.path);
      console.log(`Installed managed Toolip pre-commit block: ${result.hookPath}`);
      for (const warning of result.warnings) console.log(warning);
    });

  hook
    .command('uninstall')
    .description('Remove only the Toolip-managed block, preserving existing hooks.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .requiredOption('--yes', 'Explicitly authorize removal of the Toolip-managed block.')
    .action(async (options: { path: string }) => {
      const result = await uninstallPreCommitHookDetailed(options.path);
      console.log(
        result.removed
          ? `Toolip managed block removed: ${result.hookPath}`
          : 'No Toolip managed block was present.'
      );
    });
}
