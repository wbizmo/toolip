import { realpath } from 'node:fs/promises';
import path from 'node:path';
import { ToolipError } from '../errors/toolip-error.js';

export type WorkspaceBoundary = {
  allowedRoots: readonly string[];
  resolve(requestedRoot: string): Promise<string>;
};

function isWithin(allowedRoot: string, candidate: string): boolean {
  const relative = path.relative(allowedRoot, candidate);
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

async function canonicalizeAllowedRoots(
  roots: readonly string[]
): Promise<string[]> {
  const canonical = await Promise.all(
    roots.map(async (root) => realpath(path.resolve(root)))
  );

  return [...new Set(canonical)];
}

export async function createWorkspaceBoundary(
  roots: readonly string[]
): Promise<WorkspaceBoundary> {
  if (roots.length === 0) {
    throw new ToolipError('At least one MCP workspace root is required.', {
      code: 'MCP_WORKSPACE_REQUIRED'
    });
  }

  const allowedRoots = await canonicalizeAllowedRoots(roots);

  return {
    allowedRoots,
    async resolve(requestedRoot: string): Promise<string> {
      let candidate: string;

      try {
        candidate = await realpath(path.resolve(requestedRoot));
      } catch {
        throw new ToolipError(
          'The requested MCP workspace path does not exist or cannot be resolved.',
          { code: 'MCP_WORKSPACE_UNRESOLVABLE' }
        );
      }

      if (!allowedRoots.some((allowedRoot) => isWithin(allowedRoot, candidate))) {
        throw new ToolipError(
          'The requested path is outside the approved MCP workspace.',
          { code: 'MCP_WORKSPACE_DENIED' }
        );
      }

      return candidate;
    }
  };
}
