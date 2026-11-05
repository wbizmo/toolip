import type { Command } from 'commander';
import type { AnalyzerCommandDeps } from '../application/analyzer-command.js';
import {
  assessExecution,
  assessmentJson,
  finishAnalysis
} from '../application/analysis-status.js';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import {
  ReachabilityAnalyzer,
  type PackageReachability
} from '../analyzers/reachability/reachability-analyzer.js';

type ReachabilityOptions = {
  path: string;
  json?: boolean;
  includeDev?: boolean;
  failOnIncomplete?: boolean;
};

export function registerReachabilityCommand(
  program: Command,
  deps: AnalyzerCommandDeps = {}
): void {
  program
    .command('reachability')
    .description(
      'Show which npm packages are observed in JavaScript and TypeScript source imports.'
    )
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .option('--json', 'Print structured JSON output.')
    .option('--include-dev', 'Include development dependencies.')
    .option(
      '--no-fail-on-incomplete',
      'Do not exit 3 when some source files were not analyzed (the run is still reported as partial).'
    )
    .action(async (options: ReachabilityOptions) => {
      const runner = new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: deps.timeoutMs ?? 60_000
      });

      const [result] = await runner.run(
        [deps.analyzer ?? new ReachabilityAnalyzer()],
        {
          root: options.path
        }
      );

      if (!result) {
        throw new Error('The reachability analyzer returned no result.');
      }

      const allPackages = (result.metadata?.packages ??
        []) as PackageReachability[];

      const packages = options.includeDev
        ? allPackages
        : allPackages.filter((item) => !item.development);

      const assessment = assessExecution(result);
      const finish = () =>
        finishAnalysis({
          assessment,
          findings: [],
          failOnIncomplete: options.failOnIncomplete,
          quiet: options.json
        });

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              analyzer: result.analyzer,
              durationMs: result.durationMs,
              analysis: assessmentJson(assessment),
              packages,
              warnings: result.warnings ?? []
            },
            null,
            2
          )
        );
        finish();
        return;
      }

      console.log('Toolip Package Reachability');
      console.log('');

      for (const item of packages) {
        console.log(`${item.state.padEnd(18)} ${item.packageName}`);

        for (const reference of item.references.slice(0, 5)) {
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
      for (const warning of result.warnings ?? []) {
        console.log(`Warning: ${warning}`);
      }
      finish();
    });
}
