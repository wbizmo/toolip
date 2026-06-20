import chalk from 'chalk';
import type { ProjectProfile } from '../core/profile-project.js';
import type { ScannerContext } from '../core/scanner-context.js';
import type { ToolipReport } from '../core/report.js';

export function printProfile(profile: ProjectProfile): void {
  console.log(chalk.bold('Toolip Project Profile'));
  console.log('');
  console.log(`${chalk.dim('Root:')} ${profile.root}`);
  console.log(`${chalk.dim('Name:')} ${profile.name}`);
  console.log(`${chalk.dim('Version:')} ${profile.version}`);
  console.log(`${chalk.dim('Package Manager:')} ${profile.packageManager}`);

  if (profile.description) {
    console.log(`${chalk.dim('Description:')} ${profile.description}`);
  }

  console.log('');

  if (profile.detected.length === 0) {
    console.log(chalk.yellow('No major framework fingerprints detected yet.'));
  } else {
    console.log(chalk.bold('Detected Stack'));
    for (const item of profile.detected) {
      console.log(`${chalk.green('✓')} ${item}`);
    }
  }

  if (Object.keys(profile.languages).length > 0) {
    console.log('');
    console.log(chalk.bold('Language / File Signals'));
    for (const [language, count] of Object.entries(profile.languages)) {
      console.log(`${chalk.green('✓')} ${language}: ${count}`);
    }
  }

  if (profile.packageScripts.length > 0) {
    console.log('');
    console.log(chalk.bold('Package Scripts'));
    for (const script of profile.packageScripts) {
      console.log(`${chalk.green('✓')} ${script}`);
    }
  }
}

export function printScannerContext(context: ScannerContext): void {
  console.log(chalk.bold('Project Scan Context'));
  console.log('');
  console.log(`${chalk.dim('Root:')} ${context.root}`);
  console.log(`${chalk.dim('Files Indexed:')} ${context.summary.totalFiles}`);
  console.log(`${chalk.dim('Package Manager:')} ${context.profile.packageManager}`);
  console.log('');

  if (Object.keys(context.summary.extensions).length > 0) {
    console.log(chalk.bold('File Types'));
    for (const [extension, count] of Object.entries(context.summary.extensions)) {
      console.log(`${chalk.green('✓')} ${extension}: ${count}`);
    }
  }
}

export function printReportSummary(report: ToolipReport): void {
  console.log(chalk.bold('Report Summary'));
  console.log('');
  console.log(`${chalk.dim('Critical:')} ${severityColor('critical', report.summary.critical)}`);
  console.log(`${chalk.dim('High:')} ${severityColor('high', report.summary.high)}`);
  console.log(`${chalk.dim('Medium:')} ${severityColor('medium', report.summary.medium)}`);
  console.log(`${chalk.dim('Low:')} ${severityColor('low', report.summary.low)}`);
  console.log(`${chalk.dim('Info:')} ${severityColor('info', report.summary.info)}`);
  console.log(`${chalk.dim('Total:')} ${report.summary.totalFindings}`);
}

function severityColor(severity: string, value: number): string {
  if (severity === 'critical') return value > 0 ? chalk.red.bold(String(value)) : chalk.green(String(value));
  if (severity === 'high') return value > 0 ? chalk.red(String(value)) : chalk.green(String(value));
  if (severity === 'medium') return value > 0 ? chalk.yellow(String(value)) : chalk.green(String(value));
  if (severity === 'low') return value > 0 ? chalk.blue(String(value)) : chalk.green(String(value));
  return chalk.dim(String(value));
}
