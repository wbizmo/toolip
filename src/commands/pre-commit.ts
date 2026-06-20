import type { Command } from 'commander';
import chalk from 'chalk';
import { runPreCommit } from '../core/pre-commit.js';

export function registerPreCommitCommand(program: Command): void {
  program
    .command('pre-commit')
    .description('Run blocking checks before a Git commit.')
    .option('-p, --path <path>', 'Project path to check.', process.cwd())
    .option('--show-findings', 'Print blocking findings.')
    .action(async (options: { path: string; showFindings?: boolean }) => {
      const result = await runPreCommit(options.path);

      console.log(chalk.bold('Toolip Pre-Commit'));
      console.log('');
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
          if (finding.file) console.log(`  ${chalk.dim('File:')} ${finding.file}`);
          if (finding.evidence) console.log(`  ${chalk.dim('Evidence:')} ${finding.evidence}`);
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
