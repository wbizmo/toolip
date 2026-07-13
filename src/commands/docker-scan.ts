import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { DockerfileAnalyzer } from '../analyzers/docker/analyzer.js';

export function registerDockerScanCommand(program: Command): void {
  program
    .command('docker-scan')
    .description('Scan Dockerfiles for risky container build patterns.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option('--json', 'Print JSON.')
    .action(async (options: { path: string; json?: boolean }) => {
      const [result] = await new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: 60_000
      }).run([new DockerfileAnalyzer()], {
        root: options.path
      });

      if (!result) throw new Error('Docker analyzer returned no result.');

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
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
    });
}
