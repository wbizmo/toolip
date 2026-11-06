import type { Command } from 'commander';
import type { AnalyzerCommandDeps } from '../application/analyzer-command.js';
import {
  assessExecution,
  assessmentJson,
  finishAnalysis
} from '../application/analysis-status.js';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { DockerfileAnalyzer } from '../analyzers/docker/analyzer.js';

type DockerScanOptions = {
  path: string;
  json?: boolean;
  failOnIncomplete?: boolean;
};

export function registerDockerScanCommand(
  program: Command,
  deps: AnalyzerCommandDeps = {}
): void {
  program
    .command('docker-scan')
    .description('Scan Dockerfiles for risky container build patterns.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option('--json', 'Print JSON.')
    .option(
      '--no-fail-on-incomplete',
      'Do not exit 3 when some Dockerfiles were not analyzed (the run is still reported as partial).'
    )
    .action(async (options: DockerScanOptions) => {
      const [result] = await new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: deps.timeoutMs ?? 60_000
      }).run([deps.analyzer ?? new DockerfileAnalyzer()], {
        root: options.path
      });

      if (!result) throw new Error('Docker analyzer returned no result.');
      const assessment = assessExecution(result);

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              analyzer: result.analyzer,
              durationMs: result.durationMs,
              analysis: assessmentJson(assessment),
              summary: result.metadata,
              findings: result.findings,
              warnings: result.warnings ?? []
            },
            null,
            2
          )
        );
        finishAnalysis({
          assessment,
          findings: result.findings,
          failOnIncomplete: options.failOnIncomplete,
          quiet: true
        });
        return;
      }

      console.log('Toolip Dockerfile Security');
      console.log('');
      console.log(`Dockerfiles: ${result.metadata?.dockerfiles ?? 0}`);
      console.log(`Findings: ${result.findings.length}`);
      console.log('');

      for (const finding of result.findings) {
        console.log(`[${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(`${finding.location?.file}:${finding.location?.line}`);
        console.log('');
      }

      for (const warning of result.warnings ?? []) {
        console.log(`Warning: ${warning}`);
      }

      finishAnalysis({
        assessment,
        findings: result.findings,
        failOnIncomplete: options.failOnIncomplete
      });
    });
}
