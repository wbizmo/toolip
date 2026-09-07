import { access } from 'node:fs/promises';
import path from 'node:path';

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'unknown';

export async function detectPackageManager(root: string): Promise<PackageManager> {
  if (await exists(path.join(root, 'pnpm-lock.yaml'))) return 'pnpm';
  if (await exists(path.join(root, 'yarn.lock'))) return 'yarn';
  if (await exists(path.join(root, 'package-lock.json'))) return 'npm';
  return 'unknown';
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
