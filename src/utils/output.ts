import chalk from 'chalk';
import type { ProjectProfile } from '../core/profile-project.js';
import type { ScannerContext } from '../core/scanner-context.js';

export function printProfile(profile: ProjectProfile): void {
  console.log(chalk.bold('Toolip Project Profile'));
  console.log('');
  console.log(`${chalk.dim('Root:')} ${profile.root}`);
  console.log(`${chalk.dim('Package Manager:')} ${profile.packageManager}`);
  console.log('');

  if (profile.detected.length === 0) {
    console.log(chalk.yellow('No major framework fingerprints detected yet.'));
    return;
  }

  console.log(chalk.bold('Detected Stack'));
  for (const item of profile.detected) {
    console.log(`${chalk.green('✓')} ${item}`);
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
