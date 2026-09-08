import { access } from 'node:fs/promises';
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
    if (await exists(path.join(root, candidate.lockfile))) {
      detected.push(candidate);
    }
  }

  if (detected.length > 1) {
    const selected = detected[0];
    warn(
      `Toolip detected multiple package-manager lockfiles (${detected.map((item) => item.lockfile).join(', ')}). ` +
      `Using ${selected.manager} by precedence (pnpm > yarn > npm). Remove stale lockfiles to make dependency resolution unambiguous.`
    );
  }

  return detected[0]?.manager ?? 'unknown';
}

export function packageManagerLockfile(manager: Exclude<PackageManager, 'unknown'>): string {
  if (manager === 'pnpm') return 'pnpm-lock.yaml';
  if (manager === 'yarn') return 'yarn.lock';
  return 'package-lock.json';
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}
