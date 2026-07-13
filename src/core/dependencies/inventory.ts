import { readFile } from 'node:fs/promises';
import path from 'node:path';

export type DependencyIdentity = {
  ecosystem: 'npm';
  name: string;
  version: string;
  direct: boolean;
  development: boolean;
  source: 'package-lock';
};

type PackageLockV2 = {
  packages?: Record<string, {
    name?: string;
    version?: string;
    dev?: boolean;
  }>;
};

function packageNameFromLockPath(lockPath: string): string | undefined {
  const marker = 'node_modules/';
  const markerIndex = lockPath.lastIndexOf(marker);
  if (markerIndex === -1) return undefined;
  return lockPath.slice(markerIndex + marker.length);
}

function isDirectPackagePath(lockPath: string): boolean {
  if (!lockPath.startsWith('node_modules/')) return false;
  const remainder = lockPath.slice('node_modules/'.length);
  if (remainder.startsWith('@')) return remainder.split('/').length === 2;
  return !remainder.includes('/');
}

export async function readNpmDependencyInventory(root: string): Promise<DependencyIdentity[]> {
  const raw = await readFile(path.join(root, 'package-lock.json'), 'utf8');
  const lockfile = JSON.parse(raw) as PackageLockV2;

  if (!lockfile.packages) {
    throw new Error('Toolip requires package-lock.json lockfileVersion 2 or newer.');
  }

  const dependencies = new Map<string, DependencyIdentity>();

  for (const [lockPath, entry] of Object.entries(lockfile.packages)) {
    if (lockPath === '' || !entry.version) continue;
    const name = entry.name ?? packageNameFromLockPath(lockPath);
    if (!name) continue;

    const identity: DependencyIdentity = {
      ecosystem: 'npm',
      name,
      version: entry.version,
      direct: isDirectPackagePath(lockPath),
      development: Boolean(entry.dev),
      source: 'package-lock'
    };

    dependencies.set(`npm:${identity.name}@${identity.version}`, identity);
  }

  return [...dependencies.values()].sort((a, b) =>
    `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`)
  );
}
