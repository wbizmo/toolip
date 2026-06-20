import type { Command } from 'commander';
import chalk from 'chalk';
import { createScannerContext } from '../core/scanner-context.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
import { runSecurityDoctor } from '../core/security-doctor.js';
import { TOOLIP_VERSION } from '../config/version.js';
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

      const doctor = await runSecurityDoctor(context.root);

      const report = createReport({
        version: TOOLIP_VERSION,
        command: 'doctor',
        root: context.root,
        findings: doctor.findings
      });

      console.log('');
      console.log(chalk.bold('Security Hygiene'));
      console.log(`${chalk.dim('Files Scanned:')} ${doctor.summary.filesScanned}`);
      console.log(`${chalk.dim('Secrets:')} ${doctor.summary.secrets}`);
      console.log(`${chalk.dim('Dangerous Code:')} ${doctor.summary.dangerousCode}`);
      console.log(`${chalk.dim('Configuration:')} ${doctor.summary.configuration}`);
      console.log(`${chalk.dim('Security Headers:')} ${doctor.summary.headers}`);

      console.log('');
      printReportSummary(report);

      if (options.output) {
        await writeReport(options.output, report);
        console.log('');
        console.log(`${chalk.green('✓')} Report written to ${options.output}`);
      }
    });
}
