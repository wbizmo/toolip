import type { Command } from 'commander';
import chalk from 'chalk';
import { runPreCommit } from '../core/pre-commit.js';

export function registerPreCommitCommand(program: Command): void {
  program
    .command('pre-commit')
    .description('Run blocking checks before a Git commit.')
    .option('-p, --path <path>', 'Project path to check.', process.cwd())
    .option('--full', 'Run an explicit full-repository check instead of staged-only analysis.')
    .option('--show-findings', 'Print blocking findings.')
    .action(async (options: { path: string; full?: boolean; showFindings?: boolean }) => {
      const result = await runPreCommit(options.path, { full: options.full });

      console.log(chalk.bold('Toolip Pre-Commit'));
      console.log('');
      console.log(`${chalk.dim('Scope:')} ${result.scope}`);
      console.log(`${chalk.dim('Files considered:')} ${result.filesConsidered}`);
      console.log(`${chalk.dim('Critical:')} ${result.summary.critical}`);
      console.log(`${chalk.dim('High:')} ${result.summary.high}`);
      console.log(`${chalk.dim('Blocking Findings:')} ${result.summary.blocking}`);

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
            console.log(`  ${chalk.dim('Evidence:')} ${finding.evidence[0].summary}`);
          }
        }
      }

      if (!result.passed) {
        console.log('');
        console.log(chalk.red('Pre-commit checks failed. Fix critical/high findings before committing.'));
        process.exitCode = 1;
        return;
      }

      console.log('');
      console.log(chalk.green('Pre-commit checks passed.'));
    });
}
