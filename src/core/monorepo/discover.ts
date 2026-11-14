import { realpath } from 'node:fs/promises';
import path from 'node:path';
import fg from 'fast-glob';
import { readBoundedDependencyText } from '../dependencies/lockfile-resolvers.js';
import { TextFileReader } from '../text-file-reader.js';

type RootManifest = {
  workspaces?: string[] | { packages?: string[] };
};

export type WorkspaceProject = {
  root: string;
  relativePath: string;
  name?: string;
  version?: string;
};

const maximumWorkspacePatterns = 256;
const maximumWorkspaceProjects = 10_000;
const maximumWorkspaceManifestBytes = 1024 * 1024;
const maximumWorkspaceManifestTotalBytes = 32 * 1024 * 1024;

async function patterns(root: string): Promise<string[]> {
  const manifest = JSON.parse(
    await readBoundedDependencyText(
      path.join(root, 'package.json'),
      maximumWorkspaceManifestBytes
    )
  ) as RootManifest;

  if (Array.isArray(manifest.workspaces)) return manifest.workspaces;
  if (Array.isArray(manifest.workspaces?.packages))
    return manifest.workspaces.packages;

  try {
    const yaml = await readBoundedDependencyText(
      path.join(root, 'pnpm-workspace.yaml'),
      maximumWorkspaceManifestBytes
    );
    return yaml
      .split(/\r?\n/u)
      .map((line) => line.match(/^\s*-\s*['"]?([^'"]+)['"]?\s*$/u)?.[1])
      .filter((value): value is string => Boolean(value));
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'code' in error &&
      error.code === 'ENOENT'
    )
      return [];
    throw error;
  }
}

export async function discoverWorkspaces(
  root: string
): Promise<WorkspaceProject[]> {
  const absoluteRoot = await realpath(path.resolve(root));
  const workspacePatterns = await patterns(absoluteRoot);

  if (workspacePatterns.length === 0) {
    return [{ root: absoluteRoot, relativePath: '.' }];
  }

  if (
    workspacePatterns.length > maximumWorkspacePatterns ||
    workspacePatterns.some((pattern) => !isSafeWorkspacePattern(pattern))
  ) {
    throw new Error(
      'Workspace patterns are unsafe or exceed the configured limit.'
    );
  }

  const stream = fg.stream(
    workspacePatterns.map(
      (pattern) => `${pattern.replace(/\/$/u, '')}/package.json`
    ),
    {
      cwd: absoluteRoot,
      absolute: false,
      onlyFiles: true,
      unique: true,
      followSymbolicLinks: false,
      ignore: ['**/.git/**', '**/node_modules/**', '**/dist/**']
    }
  ) as unknown as AsyncIterable<string | { path: string }> & {
    destroy?: () => void;
  };
  const manifests: string[] = [];
  for await (const item of stream) {
    const manifestPath = typeof item === 'string' ? item : item.path;
    manifests.push(manifestPath);
    if (manifests.length > maximumWorkspaceProjects) {
      stream.destroy?.();
      throw new Error(
        `Workspace discovery exceeds the ${maximumWorkspaceProjects}-project limit.`
      );
    }
  }

  const reader = new TextFileReader(
    {
      maxFiles: maximumWorkspaceProjects,
      maxFileBytes: maximumWorkspaceManifestBytes,
      maxTotalBytes: maximumWorkspaceManifestTotalBytes
    },
    { root: absoluteRoot }
  );
  const projects: WorkspaceProject[] = [];
  for (const manifestPath of manifests.sort()) {
    const normalized = path.posix.normalize(manifestPath.replaceAll('\\', '/'));
    if (
      path.posix.isAbsolute(normalized) ||
      normalized.startsWith('../') ||
      normalized.includes('\0') ||
      (normalized !== 'package.json' && !normalized.endsWith('/package.json'))
    ) {
      throw new Error('Workspace manifest path is outside the project root.');
    }
    const read = await reader.read(path.join(absoluteRoot, normalized));
    if (read.status !== 'ok')
      throw new Error(
        `Workspace manifest scan is incomplete (${read.status}).`
      );
    const manifest = JSON.parse(read.content) as {
      name?: string;
      version?: string;
    };
    const workspaceRoot = path.dirname(path.join(absoluteRoot, normalized));
    projects.push({
      root: workspaceRoot,
      relativePath: path.relative(absoluteRoot, workspaceRoot) || '.',
      name: manifest.name,
      version: manifest.version
    });
  }
  return projects;
}

function isSafeWorkspacePattern(pattern: string): boolean {
  const normalized = pattern.replaceAll('\\', '/');
  return (
    normalized.length > 0 &&
    normalized.length <= 512 &&
    !path.posix.isAbsolute(normalized) &&
    !normalized.split('/').includes('..') &&
    !normalized.includes('\0')
  );
}
