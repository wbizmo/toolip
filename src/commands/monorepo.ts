import type { Command } from 'commander';
import { discoverWorkspaces } from '../core/monorepo/discover.js';

export function registerMonorepoCommand(program: Command): void {
  program
    .command('monorepo')
    .description('Discover and summarize workspace packages.')
    .option('-p, --path <path>', 'Repository path.', process.cwd())
    .option('--json', 'Print JSON.')
    .action(async (options: { path: string; json?: boolean }) => {
      const workspaces = await discoverWorkspaces(options.path);

      if (options.json) {
        console.log(JSON.stringify({ workspaces }, null, 2));
        return;
      }

      console.log('Toolip Monorepo Discovery');
      console.log('');
      for (const workspace of workspaces) {
        console.log(`${workspace.relativePath} ${workspace.name ?? ''}`.trim());
      }
    });
}
