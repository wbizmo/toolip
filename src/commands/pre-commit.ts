import type { Command } from 'commander';
import chalk from 'chalk';
import { EXIT_CODES } from '../application/exit-codes.js';
import { isFailOn } from '../application/analysis-status.js';
import { ToolipError } from '../errors/toolip-error.js';
import { runPreCommit } from '../core/pre-commit.js';

export function registerPreCommitCommand(program: Command): void {
  program
    .command('pre-commit')
    .description('Run blocking checks before a Git commit.')
    .option('-p, --path <path>', 'Project path to check.', process.cwd())
    .option(
      '--full',
      'Run an explicit full-repository check instead of staged-only analysis.'
    )
    .option('--show-findings', 'Print blocking findings.')
    .option(
      '--fail-on <severity>',
      'Block at or above: critical, high, medium, low, none.',
      'high'
    )
    .option(
      '--no-fail-on-incomplete',
      'Do not block when eligible staged files could not be scanned (reported as partial; NOT recommended).'
    )
    .action(
      async (options: {
        path: string;
        full?: boolean;
        showFindings?: boolean;
        failOn?: string;
        failOnIncomplete?: boolean;
      }) => {
        if (!isFailOn(options.failOn)) {
          throw new ToolipError(
            `Invalid --fail-on value "${options.failOn}". Use critical, high, medium, low, info or none.`,
            { code: 'INVALID_FAIL_ON', exitCode: 1 }
          );
        }
        const result = await runPreCommit(options.path, {
          full: options.full,
          failOn: options.failOn,
          failOnIncomplete: options.failOnIncomplete
        });

        console.log(chalk.bold('Toolip Pre-Commit'));
        console.log('');
        console.log(`${chalk.dim('Scope:')} ${result.scope}`);
        console.log(
          `${chalk.dim('Files considered:')} ${result.filesConsidered}`
        );
        console.log(`${chalk.dim('Critical:')} ${result.summary.critical}`);
        console.log(`${chalk.dim('High:')} ${result.summary.high}`);
        console.log(
          `${chalk.dim('Blocking Findings:')} ${result.summary.blocking}`
        );

        const coverage = result.coverage;
        console.log(
          `${chalk.dim('Analysis:')} ${coverage.state.toUpperCase()} (${coverage.scanned}/${coverage.eligible} eligible scanned, ${coverage.skipped} skipped, ${coverage.failed} failed${coverage.excluded === undefined ? '' : `, ${coverage.excluded} excluded`})`
        );
        if (coverage.state !== 'complete' && coverage.reason) {
          console.log(`${chalk.dim('Reason:')} ${coverage.reason}`);
        }

        if (result.warnings.length > 0) {
          console.log('');
          console.log(
            chalk.yellow(`Not content-scanned (${result.warnings.length}):`)
          );
          for (const warning of result.warnings) {
            console.log(`  ${chalk.yellow('!')} ${warning}`);
          }
        }

        if (options.showFindings && result.findings.length > 0) {
          console.log('');
          console.log(chalk.bold('Blocking Findings'));

          for (const finding of result.findings.filter(
            (item) => item.severity === 'critical' || item.severity === 'high'
          )) {
            console.log(`${chalk.red('✖')} ${finding.title}`);
            if (finding.location?.file) {
              console.log(`  ${chalk.dim('File:')} ${finding.location.file}`);
            }
            if (finding.evidence?.[0]?.summary) {
              console.log(
                `  ${chalk.dim('Evidence:')} ${finding.evidence[0].summary}`
              );
            }
          }
        }

        if (!result.passed) {
          console.log('');
          console.log(
            chalk.red(
              result.blockedByIncompleteScan
                ? 'Pre-commit blocked: the scan was incomplete, so the result is not an all-clear. Exclude the listed files in .toolipignore if they are intentionally out of scope, or fix the read problem.'
                : 'Pre-commit checks failed. Fix blocking findings before committing.'
            )
          );
          // 1 = blocking findings (compatible with existing hooks), 3 = incomplete scan.
          process.exitCode = result.blockedByIncompleteScan
            ? result.coverage.state === 'failed'
              ? EXIT_CODES.failed
              : EXIT_CODES.incomplete
            : EXIT_CODES.error;
          return;
        }

        console.log('');
        console.log(chalk.green('Pre-commit checks passed.'));
      }
    );
}
