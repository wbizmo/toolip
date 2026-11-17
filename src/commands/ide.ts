import type { Command } from 'commander';
import { serveIdeJsonRpc } from '../integrations/ide/server.js';

export function registerIdeCommand(program: Command): void {
  program.command('ide')
    .description('Local, read-only IDE analysis protocol.')
    .command('serve')
    .description('Serve bounded JSON-RPC diagnostics over stdio; no network or workspace commands.')
    .action(async () => {
      await serveIdeJsonRpc();
    });
}
