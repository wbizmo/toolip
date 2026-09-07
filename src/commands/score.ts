import type { Command } from 'commander';
import chalk from 'chalk';
import { buildSecurityScorecard } from '../application/security-scorecard.js';
import type { ScoreDimension } from '../core/score.js';

export function registerScoreCommand(program: Command): void {
  program
    .command('score')
    .description(
      'Calculate a Toolip security scorecard from executed security checks.'
    )
    .option(
      '-p, --path <path>',
      'Project path to score.',
      process.cwd()
    )
    .option('--json', 'Print structured JSON output.')
    .action(async (options: { path: string; json?: boolean }) => {
      const scorecard = await buildSecurityScorecard(options.path);

      if (options.json) {
        console.log(JSON.stringify(scorecard, null, 2));
        return;
      }

      console.log(chalk.bold('Toolip Security Scorecard'));
      console.log('');
      printDimension('Dependency Health ....', scorecard.score.dimensions.dependencyHealth);
      printDimension('Secret Hygiene .......', scorecard.score.dimensions.secretHygiene);
      printDimension('Configuration ........', scorecard.score.dimensions.configurationSecurity);
      printDimension('Git Safety ...........', scorecard.score.dimensions.gitSafety);
      console.log('');
      console.log(
        `${chalk.dim('Overall Score ........')} ${
          scorecard.score.overall ?? 'N/A (incomplete)'
        }`
      );
      console.log(
        `${chalk.dim('Grade ................')} ${
          scorecard.score.grade ?? 'N/A'
        }`
      );

      if (scorecard.dependencyHealth) {
        console.log('');
        console.log(chalk.dim('Dependency score breakdown'));
        console.log(
          `${chalk.dim('Vulnerability penalty')} ${scorecard.dependencyHealth.vulnerabilityPenalty}`
        );
        console.log(
          `${chalk.dim('Deprecation penalty ..')} ${scorecard.dependencyHealth.deprecationPenalty}`
        );
        console.log(
          `${chalk.dim('Maintenance penalty ..')} ${scorecard.dependencyHealth.maintenancePenalty}`
        );
        console.log(
          `${chalk.dim('Freshness penalty ....')} ${scorecard.dependencyHealth.freshnessPenalty}`
        );
      }

      if (scorecard.warnings.length > 0) {
        console.log('');
        console.log(chalk.yellow('Incomplete/partial analysis:'));
        for (const warning of scorecard.warnings) {
          console.log(`- ${warning}`);
        }
      }
    });
}

function printDimension(label: string, dimension: ScoreDimension): void {
  const value = dimension.score ?? 'N/A';
  const status = dimension.status === 'measured'
    ? ''
    : ` (${dimension.status})`;
  console.log(`${chalk.dim(label)} ${value}${status}`);
  if (dimension.reason) {
    console.log(`  ${chalk.dim(dimension.reason)}`);
  }
}
