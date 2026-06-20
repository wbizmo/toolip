import type { Command } from 'commander';
import chalk from 'chalk';
import { runGitAudit } from '../core/git-audit.js';
import { createReport } from '../core/report.js';
import { writeReport } from '../core/report-writer.js';
import { TOOLIP_VERSION } from '../config/version.js';
import { printReportSummary } from '../utils/output.js';

export function registerGitAuditCommand(program: Command): void {
  program
    .command('git-audit')
    .description('Audit Git safety, ignored files, and dangerous committed-file patterns.')
    .option('-p, --path <path>', 'Project path to audit.', process.cwd())
    .option('-o, --output <file>', 'Write Git audit report to JSON or Markdown.')
    .action(async (options: { path: string; output?: string }) => {
      const result = await runGitAudit(options.path);

      console.log(chalk.bold('Toolip Git Audit'));
      console.log('');
      console.log(`${chalk.dim('Files Checked:')} ${result.summary.filesChecked}`);
      console.log(`${chalk.dim('Dangerous Files:')} ${result.summary.dangerousFiles}`);
      console.log(`${chalk.dim('.gitignore Present:')} ${result.summary.gitignorePresent ? 'yes' : 'no'}`);
      console.log(`${chalk.dim('.env Ignored:')} ${result.summary.envIgnored ? 'yes' : 'no'}`);
      console.log(`${chalk.dim('PEM Ignored:')} ${result.summary.pemIgnored ? 'yes' : 'no'}`);

      const report = createReport({
        version: TOOLIP_VERSION,
        command: 'git-audit',
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
    });
}
