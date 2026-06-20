import chalk from 'chalk';
import type { PackageHealth } from '../core/dependency-types.js';
import type { PackageComparison } from '../core/compare-packages.js';

export function printPackageHealth(pkg: PackageHealth): void {
  console.log(chalk.bold(`Package: ${pkg.name}`));
  console.log('');
  console.log(`${chalk.dim('Installed Version:')} ${pkg.installedVersion}`);
  console.log(`${chalk.dim('Latest Version:')} ${pkg.latestVersion ?? 'unknown'}`);
  console.log(`${chalk.dim('Outdated:')} ${pkg.outdated ? chalk.yellow('yes') : chalk.green('no')}`);
  console.log(`${chalk.dim('Deprecated:')} ${pkg.deprecated ? chalk.red('yes') : chalk.green('no')}`);
  console.log(`${chalk.dim('Maintainers:')} ${pkg.maintainers}`);
  console.log(`${chalk.dim('Published:')} ${pkg.publishedAt ?? 'unknown'}`);
  console.log(`${chalk.dim('Age:')} ${pkg.ageInDays === null ? 'unknown' : `${pkg.ageInDays} days`}`);
  console.log(`${chalk.dim('Risk Score:')} ${formatRisk(pkg.riskScore)}`);
}

export function printPackageComparison(comparison: PackageComparison): void {
  console.log(chalk.bold('Toolip Package Comparison'));
  console.log('');

  for (const pkg of comparison.packages) {
    console.log(`${chalk.bold(pkg.name)}`);
    console.log(`  Latest .......... ${pkg.latestVersion ?? 'unknown'}`);
    console.log(`  Deprecated ...... ${pkg.deprecated ? chalk.red('yes') : chalk.green('no')}`);
    console.log(`  Maintainers ..... ${pkg.maintainers}`);
    console.log(`  Age ............. ${pkg.ageInDays === null ? 'unknown' : `${pkg.ageInDays} days`}`);
    console.log(`  Risk Score ...... ${formatRisk(pkg.riskScore)}`);
    console.log('');
  }

  if (comparison.safest) {
    console.log(`${chalk.green('Safest:')} ${comparison.safest.name} (${comparison.safest.riskScore})`);
  }

  if (comparison.riskiest) {
    console.log(`${chalk.red('Riskiest:')} ${comparison.riskiest.name} (${comparison.riskiest.riskScore})`);
  }
}

function formatRisk(score: number): string {
  if (score >= 70) return chalk.red.bold(String(score));
  if (score >= 40) return chalk.yellow(String(score));
  return chalk.green(String(score));
}
