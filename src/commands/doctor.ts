import type { Command } from 'commander';
import chalk from 'chalk';
import { createScannerContext } from '../core/scanner-context.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
import { printReportSummary, printScannerContext } from '../utils/output.js';

export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Run a full project security hygiene audit.')
    .option('-p, --path <path>', 'Project path to audit.', process.cwd())
    .option('-o, --output <file>', 'Write doctor report to JSON or Markdown.')
    .action(async (options: { path: string; output?: string }) => {
      console.log(chalk.bold('Toolip Doctor'));
      console.log('');

      const context = await createScannerContext(options.path);
      printScannerContext(context);

      const report = createReport({
        version: '0.1.0',
        command: 'doctor',
        root: context.root,
        findings: [
          {
            id: 'TOOLIP-DOCTOR-FOUNDATION',
            title: 'Security doctor foundation active',
            severity: 'info',
            category: 'security-hygiene',
            message: 'Toolip has prepared the project context for security hygiene analysis.',
            recommendation: 'Run Sprint 3 commands after secret and dangerous-pattern scanners are added.'
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
      console.log(chalk.yellow('Security checks arrive in Sprint 3.'));
    });
}
