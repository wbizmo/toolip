import type { Command } from 'commander';
import chalk from 'chalk';
import { createScannerContext } from '../core/scanner-context.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
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

      const report = createReport({
        version: TOOLIP_VERSION,
        command: 'scan',
        root: context.root,
        findings: [
          {
            id: 'TOOLIP-SCAN-FOUNDATION',
            title: 'Supply chain scanner foundation active',
            severity: 'info',
            category: 'supply-chain',
            message: 'Toolip has indexed the project and prepared the scan context.',
            recommendation: 'Run Sprint 2 commands after dependency intelligence is added.'
          }
        ]
      });

      console.log('');
      printReportSummary(report);

      if (options.output) {
        await writeReport(options.output, report);
        console.log('');
        console.log(`${chalk.green('✓')} Report written to ${options.output}`);
      }

      console.log('');
      console.log(chalk.yellow('Supply chain analysis arrives in Sprint 2.'));
    });
}
