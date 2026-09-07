import type { Command } from 'commander';
import chalk from 'chalk';
import { buildSecurityScorecard } from '../application/security-scorecard.js';
import { TOOLIP_VERSION } from '../config/version.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
import { createScannerContext } from '../core/scanner-context.js';
import { printReportSummary, printScannerContext } from '../utils/output.js';

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan project dependencies and security hygiene indicators.')
    .option('-p, --path <path>', 'Project path to scan.', process.cwd())
    .option('-o, --output <file>', 'Write scan report to JSON or Markdown.')
    .action(async (options: { path: string; output?: string }) => {
      console.log(chalk.bold('Toolip Scan'));
      console.log('');

      const context = await createScannerContext(options.path);
      printScannerContext(context);

      const scorecard = await buildSecurityScorecard(context.root);
      const report = createReport({
        version: TOOLIP_VERSION,
        command: 'scan',
        root: context.root,
        findings: scorecard.findings
      });

      if (scorecard.dependencySummary) {
        const summary = scorecard.dependencySummary;
        console.log('');
        console.log(chalk.bold('Dependency Intelligence'));
        console.log(`${chalk.dim('Total Dependencies:')} ${summary.totalDependencies}`);
        console.log(`${chalk.dim('Outdated:')} ${summary.outdated}`);
        console.log(`${chalk.dim('Deprecated:')} ${summary.deprecated}`);
        console.log(`${chalk.dim('High Risk:')} ${summary.highRisk}`);
        console.log(`${chalk.dim('Medium Risk:')} ${summary.mediumRisk}`);
        console.log(`${chalk.dim('Average Risk:')} ${summary.averageRiskScore}`);
      }

      console.log(
        `${chalk.dim('Dependency Health:')} ${scorecard.score.dependencyHealth ?? 'N/A'}`
      );
      console.log(
        `${chalk.dim('Overall Grade:')} ${scorecard.score.grade ?? 'N/A (incomplete)'}`
      );

      console.log('');
      printReportSummary(report);

      if (scorecard.warnings.length > 0) {
        console.log('');
        console.log(chalk.yellow('Partial analysis warnings:'));
        for (const warning of scorecard.warnings) {
          console.log(`- ${warning}`);
        }
      }

      if (options.output) {
        await writeReport(options.output, report);
        console.log('');
        console.log(`${chalk.green('✓')} Report written to ${options.output}`);
      }
    });
}
