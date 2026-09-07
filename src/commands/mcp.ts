import type { Command } from 'commander';
import { startMcpServer } from '../mcp/server.js';

type McpOptions = {
  allowRoot?: string[];
};

export function registerMcpCommand(program: Command): void {
  program
    .command('mcp')
    .description('Start the Toolip MCP server over stdio.')
    .option(
      '--allow-root <paths...>',
      'Approved workspace roots available to MCP tools.',
      [process.cwd()]
    )
    .action(async (options: McpOptions) => {
      await startMcpServer({
        allowedRoots: options.allowRoot ?? [process.cwd()]
      });
    });
}
