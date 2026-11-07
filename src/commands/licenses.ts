import type { Command } from 'commander';
import chalk from 'chalk';
import { analyzeLicenses } from '../core/license-analysis.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
import { TOOLIP_VERSION } from '../config/version.js';
import { printReportSummary } from '../utils/output.js';

export function registerLicensesCommand(program: Command): void {
  program
    .command('licenses')
    .description('Analyze dependency license inventory and restrictive license signals.')
    .option('-p, --path <path>', 'Project path to analyze.', process.cwd())
    .option('-o, --output <file>', 'Write license report to JSON or Markdown.')
    .option('--offline', 'Disable deps.dev metadata requests.')
    .option(
      '--allow-public-scope',
      'Consent to sending scoped npm package names to deps.dev.'
    )
    .option('--concurrency <count>', 'Maximum concurrent metadata lookups.', '8')
    .action(
      async (options: {
        path: string;
        output?: string;
        offline?: boolean;
        allowPublicScope?: boolean;
        concurrency: string;
      }) => {
      const concurrency = Number(options.concurrency);
      if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 32)
        throw new Error('--concurrency must be between 1 and 32');
      const result = await analyzeLicenses(
        options.path,
        undefined,
        undefined,
        {
          offline: options.offline,
          allowPublicScope: options.allowPublicScope,
          concurrency
        }
      );

      console.log(chalk.bold('Toolip License Analysis'));
      console.log('');
      console.log(`${chalk.dim('Total Packages:')} ${result.summary.total}`);
      console.log(`${chalk.dim('Unknown Licenses:')} ${result.summary.unknown}`);
      console.log(`${chalk.dim('Restrictive Licenses:')} ${result.summary.restrictive}`);
      console.log('');

      console.log(chalk.bold('License Distribution'));
      for (const [license, count] of Object.entries(result.summary.distribution)) {
        console.log(`${chalk.green('✓')} ${license}: ${count}`);
      }

      if (result.warnings.length > 0) {
        console.log('');
        console.log(chalk.bold('Metadata Warnings'));
        for (const warning of result.warnings) {
          console.log(`${chalk.yellow('!')} ${warning}`);
        }
      }

      const report = createReport({
        version: TOOLIP_VERSION,
        command: 'licenses',
        root: options.path,
        findings: result.findings
      });

      console.log('');
      printReportSummary(report);

      if (options.output) {
        await writeReport(options.output, report);
        console.log('');
        console.log(`${chalk.green('✓')} Report written to ${options.output}`);
      }
      }
    );
}
