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
import { OsvVulnerabilityAnalyzer } from '../analyzers/vulnerability/osv-analyzer.js';

export function registerVulnerabilitiesCommand(
  program: Command,
  deps: AnalyzerCommandDeps = {}
): void {
  program
    .command('vulnerabilities')
    .alias('vulns')
    .description('Match resolved npm dependencies against OSV.dev.')
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
      'Do not exit 3 when the lookup was only partially completed.'
    )
    .action(
      async (options: {
        path: string;
        json?: boolean;
        includeDev?: boolean;
        failOn?: string;
        failOnIncomplete?: boolean;
      }) => {
        if (!isFailOn(options.failOn)) {
          throw new ToolipError(
            `Invalid --fail-on value "${options.failOn}". Use critical, high, medium, low, info or none.`,
            { code: 'INVALID_FAIL_ON', exitCode: 1 }
          );
        }
        const failOn: FailOn = options.failOn;
        const [result] = await new AnalyzerRunner({
          concurrency: 1,
          timeoutMs: deps.timeoutMs ?? 60_000
        }).run([deps.analyzer ?? new OsvVulnerabilityAnalyzer()], {
          root: options.path
        });

        if (!result) throw new Error('OSV analyzer returned no result.');
        const assessment = assessExecution(result);

        const findings = options.includeDev
          ? result.findings
          : result.findings.filter(
              (finding) => finding.metadata?.development !== true
            );

        if (options.json) {
          console.log(
            JSON.stringify(
              { ...result, analysis: assessmentJson(assessment), findings },
              null,
              2
            )
          );
        } else if (assessment.state === 'failed') {
          console.log('Toolip Vulnerability Intelligence');
          console.log('');
          console.log(
            'Vulnerability lookup did not complete; no vulnerability result is available.'
          );
        } else {
          console.log('Toolip Vulnerability Intelligence');
          console.log('');
          console.log(
            `Dependencies checked: ${result.metadata?.dependenciesChecked ?? 0}`
          );
          console.log(`Known vulnerabilities: ${findings.length}`);
          console.log('');

          for (const finding of findings) {
            console.log(
              `[${finding.severity.toUpperCase()}] ${finding.metadata?.vulnerabilityId}`
            );
            console.log(
              `Package: ${finding.metadata?.package}@${finding.metadata?.installedVersion}`
            );
            console.log(`Summary: ${finding.title}`);
            if (finding.remediation?.summary)
              console.log(`Fix: ${finding.remediation.summary}`);
            console.log('');
          }

          if (findings.length === 0 && assessment.state === 'complete') {
            console.log(
              'No disclosed vulnerabilities matched the resolved npm dependency versions.'
            );
          }
        }

        finishAnalysis({
          assessment,
          findings,
          failOn,
          failOnIncomplete: options.failOnIncomplete,
          quiet: options.json
        });
      }
    );
}
