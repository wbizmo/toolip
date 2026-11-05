import type { Command } from 'commander';
import chalk from 'chalk';
import {
  decideExit,
  describeAssessment,
  gatedFindings,
  isFailOn
} from '../application/analysis-status.js';
import { ToolipError } from '../errors/toolip-error.js';
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
    .option(
      '--fail-on <severity>',
      'Exit 2 at or above: critical, high, medium, low, none.',
      'none'
    )
    .option(
      '--fail-on-incomplete',
      'Exit 3 when eligible files could not be scanned (partial result).'
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
        console.log(chalk.bold('Toolip Doctor'));
        console.log('');

        const context = await createScannerContext(options.path);
        printScannerContext(context);

        const doctor = await runSecurityDoctor(context);

        const report = createReport({
          version: TOOLIP_VERSION,
          command: 'doctor',
          root: context.root,
          findings: doctor.findings,
          analysis: {
            state: doctor.coverage.state,
            reasons: doctor.coverage.reason ? [doctor.coverage.reason] : []
          }
        });

        console.log('');
        console.log(chalk.bold('Security Hygiene'));
        const coverage = doctor.coverage;
        console.log(
          `${chalk.dim('Analysis:')} ${coverage.state === 'complete' ? chalk.green('COMPLETE') : chalk.yellow(coverage.state.toUpperCase())} (${coverage.scanned}/${coverage.eligible} eligible scanned, ${coverage.skipped} skipped, ${coverage.failed} failed, ${coverage.excluded ?? 0} excluded)`
        );
        if (coverage.state !== 'complete') {
          console.log(
            chalk.yellow(
              `Not an all-clear: ${coverage.reason ?? 'some eligible files were not scanned'}.`
            )
          );
        }
        console.log(
          `${chalk.dim('Files Discovered:')} ${doctor.summary.filesDiscovered}`
        );
        console.log(
          `${chalk.dim('Files Scanned:')} ${doctor.summary.filesScanned}`
        );
        console.log(
          `${chalk.dim('Files Skipped:')} ${doctor.summary.filesSkipped}`
        );
        console.log(
          `${chalk.dim('Read Failures:')} ${doctor.summary.readFailures}`
        );
        console.log(`${chalk.dim('Secrets:')} ${doctor.summary.secrets}`);
        console.log(
          `${chalk.dim('Dangerous Code:')} ${doctor.summary.dangerousCode}`
        );
        console.log(
          `${chalk.dim('Configuration:')} ${doctor.summary.configuration}`
        );
        console.log(
          `${chalk.dim('Security Headers:')} ${doctor.summary.headers}`
        );

        console.log('');
        printReportSummary(report);

        if (options.output) {
          await writeReport(options.output, report);
          console.log('');
          console.log(
            `${chalk.green('✓')} Report written to ${options.output}`
          );
        }

        const gated = gatedFindings(doctor.findings, options.failOn);
        const code = decideExit({
          state: coverage.state,
          gated: gated.length,
          failOnIncomplete: options.failOnIncomplete ?? false
        });
        if (code !== 0) {
          console.error(
            `Exit ${code}: ${describeAssessment({ state: coverage.state, reason: coverage.reason, execution: 'ok', eligible: coverage.eligible, scanned: coverage.scanned, skipped: coverage.skipped, failed: coverage.failed })}; ${gated.length} finding(s) at or above the gate.`
          );
          process.exitCode = code;
        }
      }
    );
}
