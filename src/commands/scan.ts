import type { Command } from 'commander';
import chalk from 'chalk';
import { createScannerContext } from '../core/scanner-context.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
import { scanDependencies } from '../core/dependency-scan.js';
import { calculateDependencyHealth, calculateScore } from '../core/score.js';
import { TOOLIP_VERSION } from '../config/version.js';
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

      const dependencyScan = await scanDependencies(context.root);
      const dependencyHealth = calculateDependencyHealth(dependencyScan.findings);
      const score = calculateScore({ dependencyHealth });

      const report = createReport({
        version: TOOLIP_VERSION,
        command: 'scan',
        root: context.root,
        findings: dependencyScan.findings
      });

      console.log('');
      console.log(chalk.bold('Dependency Intelligence'));
      console.log(`${chalk.dim('Total Dependencies:')} ${dependencyScan.summary.totalDependencies}`);
      console.log(`${chalk.dim('Outdated:')} ${dependencyScan.summary.outdated}`);
      console.log(`${chalk.dim('Deprecated:')} ${dependencyScan.summary.deprecated}`);
      console.log(`${chalk.dim('High Risk:')} ${dependencyScan.summary.highRisk}`);
      console.log(`${chalk.dim('Medium Risk:')} ${dependencyScan.summary.mediumRisk}`);
      console.log(`${chalk.dim('Average Risk:')} ${dependencyScan.summary.averageRiskScore}`);
      console.log(`${chalk.dim('Dependency Health:')} ${dependencyHealth}`);
      console.log(`${chalk.dim('Overall Grade:')} ${score.grade}`);

      console.log('');
      printReportSummary(report);

      if (options.output) {
        await writeReport(options.output, report);
        console.log('');
        console.log(`${chalk.green('✓')} Report written to ${options.output}`);
      }
    });
}
