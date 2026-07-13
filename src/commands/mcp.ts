import type { Command } from 'commander';
import { startMcpServer } from '../mcp/server.js';

export function registerMcpCommand(program: Command): void {
  program
    .command('mcp')
    .description('Start the Toolip MCP server over stdio.')
    .action(async () => {
      await startMcpServer();
    });
}
