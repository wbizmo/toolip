import type { Command } from 'commander';
import { createUpgradePullRequest } from '../core/github/upgrade-pr.js';

export function registerUpgradePrCommand(program: Command): void {
  program
    .command('upgrade-pr <package> <version>')
    .description('Create a tested dependency-upgrade pull request through gh.')
    .option('-p, --path <path>', 'Repository path.', process.cwd())
    .option('--dry-run', 'Validate the request without changing Git.')
    .action(async (
      packageName: string,
      version: string,
      options: { path: string; dryRun?: boolean }
    ) => {
      const result = await createUpgradePullRequest(
        options.path,
        packageName,
        version,
        Boolean(options.dryRun)
      );

      console.log(
        options.dryRun
          ? `Dry run passed. Proposed branch: ${result.branch}`
          : `Pull request created from ${result.branch}`
      );
    });
}
