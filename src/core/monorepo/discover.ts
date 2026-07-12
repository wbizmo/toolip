import { readFile } from 'node:fs/promises';
import path from 'node:path';
import fg from 'fast-glob';

type RootManifest = {
  workspaces?: string[] | {
    packages?: string[];
  };
};

export type WorkspaceProject = {
  root: string;
  relativePath: string;
  name?: string;
  version?: string;
};

async function patterns(root: string): Promise<string[]> {
  const manifest = JSON.parse(
    await readFile(path.join(root, 'package.json'), 'utf8')
  ) as RootManifest;

  if (Array.isArray(manifest.workspaces)) {
    return manifest.workspaces;
  }

  if (Array.isArray(manifest.workspaces?.packages)) {
    return manifest.workspaces.packages;
  }

  try {
    const yaml = await readFile(path.join(root, 'pnpm-workspace.yaml'), 'utf8');
    return yaml
      .split(/\r?\n/)
      .map((line) => line.match(/^\s*-\s*['"]?([^'"]+)['"]?\s*$/)?.[1])
      .filter((value): value is string => Boolean(value));
  } catch {
    return [];
  }
}

export async function discoverWorkspaces(root: string): Promise<WorkspaceProject[]> {
  const workspacePatterns = await patterns(root);

  if (workspacePatterns.length === 0) {
    return [{
      root,
      relativePath: '.'
    }];
  }

  const manifests = await fg(
    workspacePatterns.map((pattern) => `${pattern.replace(/\/$/, '')}/package.json`),
    {
      cwd: root,
      absolute: false,
      onlyFiles: true,
      ignore: ['**/node_modules/**', '**/dist/**']
    }
  );

  return Promise.all(
    manifests.sort().map(async (manifestPath) => {
      const absolute = path.join(root, manifestPath);
      const manifest = JSON.parse(await readFile(absolute, 'utf8')) as {
        name?: string;
        version?: string;
      };
      const workspaceRoot = path.dirname(absolute);

      return {
        root: workspaceRoot,
        relativePath: path.relative(root, workspaceRoot) || '.',
        name: manifest.name,
        version: manifest.version
      };
    })
  );
}
