import type { Command } from 'commander';
import { AnalyzerRunner } from '../application/analyzer-runner.js';
import { InstallScriptAnalyzer } from '../analyzers/install-scripts/install-script-analyzer.js';

type InstallScriptOptions = {
  path: string;
  json?: boolean;
  includeDev?: boolean;
};

export function registerInstallScriptsCommand(
  program: Command
): void {
  program
    .command('install-scripts')
    .description(
      'Inspect installed npm lifecycle scripts for suspicious behavior indicators.'
    )
    .option(
      '-p, --path <path>',
      'Project path to inspect.',
      process.cwd()
    )
    .option('--json', 'Print structured JSON output.')
    .option(
      '--include-dev',
      'Include development dependency findings.'
    )
    .action(async (options: InstallScriptOptions) => {
      const runner = new AnalyzerRunner({
        concurrency: 1,
        timeoutMs: 60_000
      });

      const [result] = await runner.run(
        [new InstallScriptAnalyzer()],
        {
          root: options.path
        }
      );

      if (!result) {
        throw new Error(
          'Install-script analyzer returned no result.'
        );
      }

      const findings = options.includeDev
        ? result.findings
        : result.findings.filter(
            (finding) =>
              finding.metadata?.development !== true
          );

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              analyzer: result.analyzer,
              durationMs: result.durationMs,
              summary: result.metadata,
              findings
            },
            null,
            2
          )
        );
        return;
      }

      console.log('Toolip Install-Script Analysis');
      console.log('');
      console.log(
        `Packages inspected: ${
          result.metadata?.packagesInspected ?? 0
        }`
      );
      console.log(
        `Lifecycle scripts: ${
          result.metadata?.lifecycleScripts ?? 0
        }`
      );
      console.log(`Findings: ${findings.length}`);
      console.log('');

      for (const finding of findings) {
        console.log(
          `[${finding.severity.toUpperCase()}] ${finding.title}`
        );
        console.log(
          `Package: ${finding.metadata?.package}@` +
            `${finding.metadata?.version}`
        );
        console.log(
          `Lifecycle: ${finding.metadata?.lifecycle}`
        );
        console.log(`Message: ${finding.message}`);
        console.log('');
      }

      if (findings.length === 0) {
        console.log(
          'No supported suspicious lifecycle-script indicators were found.'
        );
      }
    });
}
