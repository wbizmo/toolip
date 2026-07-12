import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { DependencyConfusionAnalyzer } from '../analyzers/dependency-confusion/analyzer.js';

export function registerDependencyConfusionCommand(
  program: Command
): void {
  program
    .command('dependency-confusion')
    .description(
      'Check internal-looking dependency names against the public npm registry.'
    )
    .option(
      '-p, --path <path>',
      'Project path.',
      process.cwd()
    )
    .option('--json', 'Print JSON.')
    .action(
      async (
        options: {
          path: string;
          json?: boolean;
        }
      ) => {
        const [result] =
          await new AnalyzerRunner({
            concurrency: 1,
            timeoutMs: 60_000
          }).run(
            [
              new DependencyConfusionAnalyzer()
            ],
            {
              root: options.path
            }
          );

        if (!result) {
          throw new Error(
            'Dependency-confusion analyzer returned no result.'
          );
        }

        if (options.json) {
          console.log(
            JSON.stringify(result, null, 2)
          );
          return;
        }

        console.log(
          'Toolip Dependency Confusion Audit'
        );
        console.log('');
        console.log(
          `Candidates: ${
            result.metadata?.candidates ?? 0
          }`
        );
        console.log(
          `Public collisions: ${result.findings.length}`
        );
        console.log('');

        for (const finding of result.findings) {
          console.log(
            `[${finding.severity.toUpperCase()}] ${finding.title}`
          );
          console.log(finding.message);
          console.log('');
        }
      }
    );
}
