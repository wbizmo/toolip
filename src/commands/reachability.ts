import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import {
  ReachabilityAnalyzer,
  type PackageReachability
} from '../analyzers/reachability/reachability-analyzer.js';

type ReachabilityOptions = {
  path: string;
  json?: boolean;
  includeDev?: boolean;
};

export function registerReachabilityCommand(
  program: Command
): void {
  program
    .command('reachability')
    .description(
      'Show which npm packages are observed in JavaScript and TypeScript source imports.'
    )
    .option(
      '-p, --path <path>',
      'Project path to inspect.',
      process.cwd()
    )
    .option('--json', 'Print structured JSON output.')
    .option(
      '--include-dev',
      'Include development dependencies.'
    )
    .action(async (options: ReachabilityOptions) => {
      const runner = new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: 60_000
      });

      const [result] = await runner.run(
        [new ReachabilityAnalyzer()],
        {
          root: options.path
        }
      );

      if (!result) {
        throw new Error(
          'The reachability analyzer returned no result.'
        );
      }

      const allPackages =
        (result.metadata?.packages ??
          []) as PackageReachability[];

      const packages = options.includeDev
        ? allPackages
        : allPackages.filter(
            (item) => !item.development
          );

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              analyzer: result.analyzer,
              durationMs: result.durationMs,
              packages
            },
            null,
            2
          )
        );
        return;
      }

      console.log('Toolip Package Reachability');
      console.log('');

      for (const item of packages) {
        console.log(
          `${item.state.padEnd(18)} ${item.packageName}`
        );

        for (const reference of item.references.slice(
          0,
          5
        )) {
          console.log(
            `  ${reference.file}:${reference.line}:` +
              `${reference.column} (${reference.kind})`
          );
        }
      }

      console.log('');
      console.log(
        'Reachability is static evidence, not proof that exploitation is impossible.'
      );
    });
}
