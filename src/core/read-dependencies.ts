import path from 'node:path';
import { readBoundedDependencyText } from './dependencies/lockfile-resolvers.js';
import type { DependencyFileSource } from './dependencies/inventory.js';
import type { DependencyInfo } from './dependency-types.js';

export async function readDependencies(
  root: string,
  fileSource?: DependencyFileSource
): Promise<DependencyInfo[]> {
  const packageJsonPath = path.join(root, 'package.json');
  const raw = fileSource
    ? readCapturedDependencyText(fileSource, 'package.json')
    : await readBoundedDependencyText(packageJsonPath);

  const pkg = JSON.parse(raw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
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

  for (const [name, version] of Object.entries(
    pkg.optionalDependencies ?? {}
  )) {
    results.push({ name, version, type: 'optionalDependency' });
  }

  for (const [name, version] of Object.entries(pkg.peerDependencies ?? {})) {
    results.push({ name, version, type: 'peerDependency' });
  }

  return results.sort((a, b) => a.name.localeCompare(b.name));
}

function readCapturedDependencyText(
  fileSource: DependencyFileSource,
  relativePath: string
): string {
  if (!fileSource.hasFile(relativePath)) {
    const error = new Error(
      `Project snapshot does not contain ${relativePath}.`
    );
    Object.assign(error, { code: 'ENOENT' });
    throw error;
  }
  const text = fileSource.readText(relativePath);
  if (text === undefined) {
    throw new Error(`Project snapshot has no text for ${relativePath}.`);
  }
  return text;
}
