import type { Command } from 'commander';
import type { AnalyzerCommandDeps } from '../application/analyzer-command.js';
import {
  assessExecution,
  assessmentJson,
  finishAnalysis,
  isFailOn,
  type FailOn
} from '../application/analysis-status.js';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { ToolipError } from '../errors/toolip-error.js';
import { InstallScriptAnalyzer } from '../analyzers/install-scripts/install-script-analyzer.js';

type InstallScriptOptions = {
  path: string;
  json?: boolean;
  includeDev?: boolean;
  failOn?: string;
  failOnIncomplete?: boolean;
};

export function registerInstallScriptsCommand(
  program: Command,
  deps: AnalyzerCommandDeps = {}
): void {
  program
    .command('install-scripts')
    .description(
      'Inspect installed npm lifecycle scripts for suspicious behavior indicators.'
    )
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .option('--json', 'Print structured JSON output.')
    .option('--include-dev', 'Include development dependency findings.')
    .option(
      '--fail-on <severity>',
      'Exit 2 at or above: critical, high, medium, low, none.',
      'none'
    )
    .option(
      '--no-fail-on-incomplete',
      'Do not exit 3 when some dependencies could not be inspected (the run is still reported as partial).'
    )
    .action(async (options: InstallScriptOptions) => {
      if (!isFailOn(options.failOn)) {
        throw new ToolipError(
          `Invalid --fail-on value "${options.failOn}". Use critical, high, medium, low, info or none.`,
          { code: 'INVALID_FAIL_ON', exitCode: 1 }
        );
      }
      const failOn: FailOn = options.failOn;
      const runner = new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: deps.timeoutMs ?? 60_000
      });

      const [result] = await runner.run(
        [deps.analyzer ?? new InstallScriptAnalyzer()],
        {
          root: options.path
        }
      );

      if (!result) {
        throw new Error('Install-script analyzer returned no result.');
      }

      const findings = options.includeDev
        ? result.findings
        : result.findings.filter(
            (finding) => finding.metadata?.development !== true
          );

      const assessment = assessExecution(result);
      const finish = () =>
        finishAnalysis({
          assessment,
          findings,
          failOn,
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
              summary: result.metadata,
              findings,
              warnings: result.warnings ?? []
            },
            null,
            2
          )
        );
        finish();
        return;
      }

      console.log('Toolip Install-Script Analysis');
      console.log('');
      console.log(
        `Packages inspected: ${result.metadata?.packagesInspected ?? 0}`
      );
      console.log(
        `Lifecycle scripts: ${result.metadata?.lifecycleScripts ?? 0}`
      );
      console.log(`Findings: ${findings.length}`);
      console.log('');

      for (const finding of findings) {
        console.log(`[${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(
          `Package: ${finding.metadata?.package}@` +
            `${finding.metadata?.version}`
        );
        console.log(`Lifecycle: ${finding.metadata?.lifecycle}`);
        console.log(`Message: ${finding.message}`);
        console.log('');
      }

      if (findings.length === 0 && assessment.state === 'complete') {
        console.log(
          'No supported suspicious lifecycle-script indicators were found.'
        );
      }

      for (const warning of result.warnings ?? []) {
        console.log(`Warning: ${warning}`);
      }

      finish();
    });
}
