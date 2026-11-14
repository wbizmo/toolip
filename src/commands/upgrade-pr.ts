import type { Command } from 'commander';
import { createUpgradePullRequest } from '../core/github/upgrade-pr.js';

export function registerUpgradePrCommand(program: Command): void {
  program
    .command('upgrade-pr <package> <version>')
    .description('Create a tested dependency-upgrade pull request through gh.')
    .option('-p, --path <path>', 'Repository path.', process.cwd())
    .option('--dry-run', 'Validate the request without changing Git.')
    .option(
      '--allow-project-tests',
      'Explicitly authorize running repository-defined tests in the isolated worktree.'
    )
    .option(
      '--allow-public-scope',
      'Consent to sending scoped dependency names to public registry and advisory providers during verification.'
    )
    .option(
      '--policy-file <file>',
      'Use a stricter versioned policy file for the isolated security comparison.'
    )
    .action(
      async (
        packageName: string,
        version: string,
        options: {
          path: string;
          dryRun?: boolean;
          allowProjectTests?: boolean;
          allowPublicScope?: boolean;
          policyFile?: string;
        }
      ) => {
        const result = await createUpgradePullRequest(
          options.path,
          packageName,
          version,
          Boolean(options.dryRun),
          undefined,
          undefined,
          {
            allowProjectTests: options.allowProjectTests === true,
            allowPublicScope: options.allowPublicScope === true,
            policyFile: options.policyFile
          }
        );

        console.log(
          options.dryRun
            ? `Dry run passed. Proposed branch: ${result.branch}`
            : `Pull request created from ${result.branch}. Baseline and candidate security checks completed; review the verification evidence in the PR.`
        );
      }
    );
}
