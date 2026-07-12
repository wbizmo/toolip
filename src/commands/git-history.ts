import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { GitHistorySecretAnalyzer } from '../analyzers/git-history/analyzer.js';

export function registerGitHistoryCommand(
  program: Command
): void {
  program
    .command('git-history')
    .description(
      'Scan added lines across Git commit history for secret-like values.'
    )
    .option(
      '-p, --path <path>',
      'Repository path.',
      process.cwd()
    )
    .option(
      '--max-commits <number>',
      'Maximum commits to scan.',
      '1000'
    )
    .option('--json', 'Print JSON.')
    .action(
      async (
        options: {
          path: string;
          maxCommits: string;
          json?: boolean;
        }
      ) => {
        const maxCommits = Math.max(
          1,
          Number.parseInt(
            options.maxCommits,
            10
          ) || 1000
        );

        const [result] =
          await new AnalyzerRunner({
            concurrency: 1,
            timeoutMs: 120_000
          }).run(
            [
              new GitHistorySecretAnalyzer(
                maxCommits
              )
            ],
            {
              root: options.path
            }
          );

        if (!result) {
          throw new Error(
            'Git-history analyzer returned no result.'
          );
        }

        if (options.json) {
          console.log(
            JSON.stringify(result, null, 2)
          );
          return;
        }

        console.log(
          'Toolip Git History Secret Audit'
        );
        console.log('');
        console.log(
          `Commits scanned: ${
            result.metadata?.commitsScanned ?? 0
          }`
        );
        console.log(
          `Findings: ${result.findings.length}`
        );
        console.log('');

        for (const finding of result.findings) {
          console.log(
            `[${finding.severity.toUpperCase()}] ${finding.title}`
          );
          console.log(
            `Commit: ${
              finding.metadata?.commit
            }`
          );
          console.log(
            `Evidence: ${
              finding.evidence?.[0]?.summary
            }`
          );
          console.log('');
        }
      }
    );
}
