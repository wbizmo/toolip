import type { Command } from 'commander';
import { securityDiff } from '../core/diff/security-diff.js';

export function registerDiffCommand(program: Command): void {
  program
    .command('diff <base> [head]')
    .description('Summarize security-relevant changes between Git revisions.')
    .option('-p, --path <path>', 'Repository path.', process.cwd())
    .option('--json', 'Print JSON.')
    .action(async (
      base: string,
      head: string | undefined,
      options: { path: string; json?: boolean }
    ) => {
      const result = await securityDiff(options.path, base, head ?? 'HEAD');

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      console.log('Toolip Security Diff');
      console.log('');
      console.log(`Range: ${result.base}..${result.head}`);
      console.log(`Changed files: ${result.files.length}`);
      console.log(`Manifest changed: ${result.packageManifestChanged}`);
      console.log(`Lockfile changed: ${result.lockfileChanged}`);
      console.log(`Dockerfiles changed: ${result.dockerfilesChanged.length}`);
      console.log(`Source files changed: ${result.sourceFilesChanged.length}`);
    });
}
