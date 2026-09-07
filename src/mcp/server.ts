import { TOOLIP_VERSION } from '../config/version.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { runSecurityDoctor } from '../core/security-doctor.js';
import { generateSbom } from '../core/sbom/generate.js';
import { securityDiff } from '../core/diff/security-diff.js';
import { createWorkspaceBoundary } from './workspace-boundary.js';

export type McpServerOptions = {
  allowedRoots?: readonly string[];
};

export async function startMcpServer(
  options: McpServerOptions = {}
): Promise<void> {
  const boundary = await createWorkspaceBoundary(
    options.allowedRoots ?? [process.cwd()]
  );
  const defaultRoot = boundary.allowedRoots[0];

  if (!defaultRoot) {
    throw new Error('MCP workspace boundary has no approved root.');
  }

  const server = new McpServer({
    name: 'toolip',
    version: TOOLIP_VERSION
  });

  server.registerTool(
    'toolip_doctor',
    {
      title: 'Toolip Security Doctor',
      description: 'Run local Toolip security checks inside an approved workspace.',
      inputSchema: {
        root: z.string().default(defaultRoot)
      }
    },
    async ({ root }) => {
      const approvedRoot = await boundary.resolve(root);
      const report = await runSecurityDoctor(approvedRoot);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(report, null, 2)
        }]
      };
    }
  );

  server.registerTool(
    'toolip_sbom',
    {
      title: 'Generate SBOM',
      description: 'Generate a local CycloneDX or SPDX SBOM inside an approved workspace.',
      inputSchema: {
        root: z.string().default(defaultRoot),
        format: z.enum(['cyclonedx', 'spdx']).default('cyclonedx')
      }
    },
    async ({ root, format }) => {
      const approvedRoot = await boundary.resolve(root);
      const report = await generateSbom(approvedRoot, format);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(report, null, 2)
        }]
      };
    }
  );

  server.registerTool(
    'toolip_diff',
    {
      title: 'Security Diff',
      description: 'Summarize security-relevant Git changes inside an approved workspace.',
      inputSchema: {
        root: z.string().default(defaultRoot),
        base: z.string(),
        head: z.string().default('HEAD')
      }
    },
    async ({ root, base, head }) => {
      const approvedRoot = await boundary.resolve(root);
      const result = await securityDiff(approvedRoot, base, head);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
