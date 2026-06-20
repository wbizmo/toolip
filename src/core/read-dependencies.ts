import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { DependencyInfo } from './dependency-types.js';

export async function readDependencies(root: string): Promise<DependencyInfo[]> {
  const packageJsonPath = path.join(root, 'package.json');
  const raw = await readFile(packageJsonPath, 'utf8');

  const pkg = JSON.parse(raw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const results: DependencyInfo[] = [];

  for (const [name, version] of Object.entries(pkg.dependencies ?? {})) {
    results.push({
      name,
      version,
      type: 'dependency'
    });
  }

  for (const [name, version] of Object.entries(pkg.devDependencies ?? {})) {
    results.push({
      name,
      version,
      type: 'devDependency'
    });
  }

  return results.sort((a, b) => a.name.localeCompare(b.name));
}
