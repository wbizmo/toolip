import chalk from 'chalk';
import type { ProjectProfile } from '../core/profile-project.js';

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
