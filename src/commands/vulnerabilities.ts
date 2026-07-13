import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { OsvVulnerabilityAnalyzer } from '../analyzers/vulnerability/osv-analyzer.js';
import { MemoryCache } from '../storage/memory-cache.js';

export function registerVulnerabilitiesCommand(program: Command): void {
  program
    .command('vulnerabilities')
    .alias('vulns')
    .description('Match resolved npm dependencies against OSV.dev.')
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .option('--json', 'Print structured JSON output.')
    .option('--include-dev', 'Include development dependency findings.')
    .action(async (options: { path: string; json?: boolean; includeDev?: boolean }) => {
      const [result] = await new AnalyzerRunner({ concurrency: 1, timeoutMs: 60000 }).run(
        [new OsvVulnerabilityAnalyzer()],
        { root: options.path, cache: new MemoryCache() }
      );

      if (!result) throw new Error('OSV analyzer returned no result.');
      const findings = options.includeDev
        ? result.findings
        : result.findings.filter((finding) => finding.metadata?.development !== true);

      if (options.json) {
        console.log(JSON.stringify({ ...result, findings }, null, 2));
      } else {
        console.log('Toolip Vulnerability Intelligence');
        console.log('');
        console.log(`Dependencies checked: ${result.metadata?.dependenciesChecked ?? 0}`);
        console.log(`Known vulnerabilities: ${findings.length}`);
        console.log('');

        for (const finding of findings) {
          console.log(`[${finding.severity.toUpperCase()}] ${finding.metadata?.vulnerabilityId}`);
          console.log(`Package: ${finding.metadata?.package}@${finding.metadata?.installedVersion}`);
          console.log(`Summary: ${finding.title}`);
          if (finding.remediation?.summary) console.log(`Fix: ${finding.remediation.summary}`);
          console.log('');
        }

        if (findings.length === 0) {
          console.log('No disclosed vulnerabilities matched the resolved npm dependency versions.');
        }
      }
    });
}
