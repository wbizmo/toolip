import type { Command } from 'commander';
import chalk from 'chalk';
import {
  decideExit,
  gatedFindings,
  isFailOn
} from '../application/analysis-status.js';
import { buildSecurityScorecard } from '../application/security-scorecard.js';
import { ToolipError } from '../errors/toolip-error.js';
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
    .option(
      '--fail-on <severity>',
      'Exit 2 at or above: critical, high, medium, low, none.',
      'none'
    )
    .option(
      '--fail-on-incomplete',
      'Exit 3 when any score dimension could not be measured (partial result).'
    )
    .action(
      async (options: {
        path: string;
        output?: string;
        failOn?: string;
        failOnIncomplete?: boolean;
      }) => {
        if (!isFailOn(options.failOn)) {
          throw new ToolipError(
            `Invalid --fail-on value "${options.failOn}". Use critical, high, medium, low, info or none.`,
            { code: 'INVALID_FAIL_ON', exitCode: 1 }
          );
        }
        console.log(chalk.bold('Toolip Scan'));
        console.log('');

        const context = await createScannerContext(options.path);
        printScannerContext(context);

        const scorecard = await buildSecurityScorecard(context.root);
        const report = createReport({
          version: TOOLIP_VERSION,
          command: 'scan',
          root: context.root,
          findings: scorecard.findings,
          analysis: scorecard.analysis
        });

        if (scorecard.dependencySummary) {
          const summary = scorecard.dependencySummary;
          console.log('');
          console.log(chalk.bold('Dependency Intelligence'));
          console.log(
            `${chalk.dim('Total Dependencies:')} ${summary.totalDependencies}`
          );
          console.log(`${chalk.dim('Outdated:')} ${summary.outdated}`);
          console.log(`${chalk.dim('Deprecated:')} ${summary.deprecated}`);
          console.log(`${chalk.dim('High Risk:')} ${summary.highRisk}`);
          console.log(`${chalk.dim('Medium Risk:')} ${summary.mediumRisk}`);
          console.log(
            `${chalk.dim('Average Risk:')} ${summary.averageRiskScore}`
          );
        }

        console.log(
          `${chalk.dim('Dependency Health:')} ${scorecard.score.dependencyHealth ?? 'N/A'}`
        );
        console.log(
          `${chalk.dim('Overall Grade:')} ${scorecard.score.grade ?? 'N/A (incomplete)'}`
        );

        console.log(
          `${chalk.dim('Analysis:')} ${scorecard.analysis.state === 'complete' ? chalk.green('COMPLETE') : chalk.yellow(scorecard.analysis.state.toUpperCase())}`
        );
        for (const reason of scorecard.analysis.reasons) {
          console.log(`  ${chalk.yellow('!')} ${reason}`);
        }
        if (scorecard.analysis.state !== 'complete') {
          console.log(
            chalk.yellow(
              'Not an all-clear: unmeasured dimensions may hide findings.'
            )
          );
        }

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
          console.log(
            `${chalk.green('✓')} Report written to ${options.output}`
          );
        }

        const code = decideExit({
          state: scorecard.analysis.state,
          gated: gatedFindings(scorecard.findings, options.failOn).length,
          failOnIncomplete: options.failOnIncomplete ?? false
        });
        if (code !== 0) {
          console.error(`Exit ${code}: analysis ${scorecard.analysis.state}.`);
          process.exitCode = code;
        }
      }
    );
}
