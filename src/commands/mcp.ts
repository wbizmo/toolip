import type { Command } from 'commander';
import { startMcpServer } from '../mcp/server.js';

type McpOptions = {
  allowRoot?: string[];
  organizationPolicy?: string;
  organizationPolicyPublicKey?: string;
  organizationPolicyKeyId?: string;
  organizationPolicyIssuer?: string;
  requireOrganizationPolicy?: boolean;
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
    .option(
      '--organization-policy <file>',
      'Signed organization policy envelope stored outside approved workspaces.'
    )
    .option(
      '--organization-policy-public-key <file>',
      'Operator-configured Ed25519 trust key stored outside approved workspaces.'
    )
    .option('--organization-policy-key-id <id>', 'Expected signer key ID.')
    .option('--organization-policy-issuer <issuer>', 'Expected signer issuer.')
    .option(
      '--require-organization-policy',
      'Fail closed if the trusted organization policy is not configured.'
    )
    .action(async (options: McpOptions) => {
      const trustOptionsPresent = Boolean(
        options.organizationPolicyPublicKey ||
        options.organizationPolicyKeyId ||
        options.organizationPolicyIssuer
      );
      if (options.organizationPolicy) {
        if (
          !options.organizationPolicyPublicKey ||
          !options.organizationPolicyKeyId ||
          !options.organizationPolicyIssuer
        )
          throw new Error(
            'organization policy requires a public key, key ID and issuer'
          );
      } else if (trustOptionsPresent) {
        throw new Error(
          'organization policy trust options require --organization-policy'
        );
      }
      await startMcpServer({
        allowedRoots: options.allowRoot ?? [process.cwd()],
        ...(options.organizationPolicy &&
        options.organizationPolicyPublicKey &&
        options.organizationPolicyKeyId &&
        options.organizationPolicyIssuer
          ? {
              organizationPolicy: {
                filePath: options.organizationPolicy,
                publicKeyPath: options.organizationPolicyPublicKey,
                trustedKeyId: options.organizationPolicyKeyId,
                trustedIssuer: options.organizationPolicyIssuer
              }
            }
          : {}),
        requireOrganizationPolicy: options.requireOrganizationPolicy
      });
    });
}
