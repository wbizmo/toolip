import type { Command } from 'commander';
import { auditRemoteRepository } from '../core/github/remote-audit.js';

export function registerAuditRepoCommand(program: Command): void {
  program
    .command('audit-repo <url>')
    .description('Audit a public GitHub repository through the authenticated gh CLI.')
    .option('--json', 'Print JSON.')
    .action(async (url: string, options: { json?: boolean }) => {
      const result = await auditRemoteRepository(url);

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      console.log('Toolip Remote Repository Audit');
      console.log('');
      console.log(`Repository: ${result.repository}`);
      console.log(`Findings: ${result.report.findings.length}`);
      console.log(`Critical: ${result.report.summary.secrets}`);
    });
}
