import type {
  Command
} from 'commander';
import chalk from 'chalk';
import {
  scanDependencies
} from '../core/dependency-scan.js';
import {
  calculateScore
} from '../core/score.js';

export function registerScoreCommand(
  program: Command
): void {
  program
    .command('score')
    .description(
      'Calculate a Toolip security scorecard for the current project.'
    )
    .option(
      '-p, --path <path>',
      'Project path to score.',
      process.cwd()
    )
    .option(
      '--json',
      'Print structured JSON output.'
    )
    .action(
      async (
        options: {
          path: string;
          json?: boolean;
        }
      ) => {
        const dependencyScan =
          await scanDependencies(options.path);

        const dependencyHealth =
          dependencyScan.dependencyHealth;

        const score = calculateScore({
          dependencyHealth:
            dependencyHealth.score
        });

        if (options.json) {
          console.log(
            JSON.stringify(
              {
                score,
                dependencyHealth,
                dependencySummary:
                  dependencyScan.summary
              },
              null,
              2
            )
          );

          return;
        }

        console.log(
          chalk.bold(
            'Toolip Security Scorecard'
          )
        );

        console.log('');

        console.log(
          `${chalk.dim(
            'Dependency Health ....'
          )} ${score.dependencyHealth}`
        );

        console.log(
          `${chalk.dim(
            'Secret Hygiene .......'
          )} ${score.secretHygiene}`
        );

        console.log(
          `${chalk.dim(
            'Configuration ........'
          )} ${score.configurationSecurity}`
        );

        console.log(
          `${chalk.dim(
            'Git Safety ...........'
          )} ${score.gitSafety}`
        );

        console.log('');

        console.log(
          `${chalk.dim(
            'Overall Score ........'
          )} ${score.overall}`
        );

        console.log(
          `${chalk.dim(
            'Grade ................'
          )} ${score.grade}`
        );

        console.log('');
        console.log(
          chalk.dim(
            'Dependency score breakdown'
          )
        );

        console.log(
          `${chalk.dim(
            'Vulnerability penalty'
          )} ${dependencyHealth.vulnerabilityPenalty}`
        );

        console.log(
          `${chalk.dim(
            'Deprecation penalty ..'
          )} ${dependencyHealth.deprecationPenalty}`
        );

        console.log(
          `${chalk.dim(
            'Maintenance penalty ..'
          )} ${dependencyHealth.maintenancePenalty}`
        );

        console.log(
          `${chalk.dim(
            'Freshness penalty ....'
          )} ${dependencyHealth.freshnessPenalty}`
        );
      }
    );
}
