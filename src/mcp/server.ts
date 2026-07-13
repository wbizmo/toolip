import { TOOLIP_VERSION } from '../config/version.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { runSecurityDoctor } from '../core/security-doctor.js';
import { generateSbom } from '../core/sbom/generate.js';
import { securityDiff } from '../core/diff/security-diff.js';

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: 'toolip',
    version: TOOLIP_VERSION
  });

  server.registerTool(
    'toolip_doctor',
    {
      title: 'Toolip Security Doctor',
      description: 'Run local Toolip security checks inside the approved workspace.',
      inputSchema: {
        root: z.string().default(process.cwd())
      }
    },
    async ({ root }) => {
      const report = await runSecurityDoctor(root);
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
      description: 'Generate a local CycloneDX or SPDX SBOM.',
      inputSchema: {
        root: z.string().default(process.cwd()),
        format: z.enum(['cyclonedx', 'spdx']).default('cyclonedx')
      }
    },
    async ({ root, format }) => {
      const report = await generateSbom(root, format);
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
      description: 'Summarize security-relevant Git changes.',
      inputSchema: {
        root: z.string().default(process.cwd()),
        base: z.string(),
        head: z.string().default('HEAD')
      }
    },
    async ({ root, base, head }) => {
      const result = await securityDiff(root, base, head);
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
