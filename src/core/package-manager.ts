import { lstat } from 'node:fs/promises';
import path from 'node:path';

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'unknown';

export type PackageManagerWarningSink = (message: string) => void;

const PACKAGE_MANAGER_CANDIDATES = [
  { manager: 'pnpm', lockfile: 'pnpm-lock.yaml' },
  { manager: 'yarn', lockfile: 'yarn.lock' },
  { manager: 'npm', lockfile: 'package-lock.json' }
] as const;

export async function detectPackageManager(
  root: string,
  warn: PackageManagerWarningSink = (message) => console.warn(message)
): Promise<PackageManager> {
  const detected: Array<(typeof PACKAGE_MANAGER_CANDIDATES)[number]> = [];

  for (const candidate of PACKAGE_MANAGER_CANDIDATES) {
    const metadata = await lstat(path.join(root, candidate.lockfile)).catch(
      (error: unknown) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT')
          return undefined;
        throw error;
      }
    );
    if (metadata && (!metadata.isFile() || metadata.isSymbolicLink())) {
      warn(
        `Toolip cannot trust ${candidate.lockfile} because it is not a regular file.`
      );
      return 'unknown';
    }
    if (metadata) {
      detected.push(candidate);
    }
  }

  if (detected.length > 1) {
    warn(
      `Toolip detected multiple package-manager lockfiles (${detected.map((item) => item.lockfile).join(', ')}). ` +
        'Package-manager selection is ambiguous; remove stale lockfiles or select a workspace explicitly.'
    );
    return 'unknown';
  }

  return detected[0]?.manager ?? 'unknown';
}

export function packageManagerLockfile(
  manager: Exclude<PackageManager, 'unknown'>
): string {
  if (manager === 'pnpm') return 'pnpm-lock.yaml';
  if (manager === 'yarn') return 'yarn.lock';
  return 'package-lock.json';
}
