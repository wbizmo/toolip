import { readFile } from 'node:fs/promises';
import path from 'node:path';

export type DependencyIdentity = {
  id: string;
  ecosystem: 'npm';
  name: string;
  version: string;
  direct: boolean;
  development: boolean;
  source: 'package-lock';
  installPath: string;
};

export type DependencyEdge = {
  from: 'root' | string;
  to: string;
  name: string;
  requirement: string;
  section: 'dependency' | 'devDependency' | 'optionalDependency' | 'peerDependency';
};

export type NpmDependencyGraph = {
  packages: DependencyIdentity[];
  edges: DependencyEdge[];
  rootDependencies: string[];
};

type PackageLockEntry = {
  name?: string;
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

type PackageLockV2 = {
  lockfileVersion?: number;
  packages?: Record<string, PackageLockEntry>;
};

function packageNameFromLockPath(lockPath: string): string | undefined {
  const marker = 'node_modules/';
  const markerIndex = lockPath.lastIndexOf(marker);
  if (markerIndex === -1) return undefined;
  return lockPath.slice(markerIndex + marker.length);
}

function identityId(
  installPath: string,
  name: string,
  version: string
): string {
  return `npm:${installPath}:${name}@${version}`;
}

function parentPackagePath(lockPath: string): string {
  const nestedMarker = '/node_modules/';
  const nestedIndex = lockPath.lastIndexOf(nestedMarker);
  if (nestedIndex !== -1) {
    return lockPath.slice(0, nestedIndex);
  }

  return '';
}

function resolveInstalledPath(
  packages: Record<string, PackageLockEntry>,
  fromPath: string,
  dependencyName: string
): string | undefined {
  let cursor = fromPath;

  while (true) {
    const candidate = cursor
      ? `${cursor}/node_modules/${dependencyName}`
      : `node_modules/${dependencyName}`;

    if (packages[candidate]?.version) {
      return candidate;
    }

    if (!cursor) return undefined;
    cursor = parentPackagePath(cursor);
  }
}

function requirements(
  entry: PackageLockEntry,
  includeDevelopment: boolean
): Array<{
  name: string;
  requirement: string;
  section: DependencyEdge['section'];
}> {
  const sections: Array<[
    DependencyEdge['section'],
    Record<string, string> | undefined
  ]> = [
    ['dependency', entry.dependencies],
    ['optionalDependency', entry.optionalDependencies],
    ['peerDependency', entry.peerDependencies]
  ];

  if (includeDevelopment) {
    sections.push(['devDependency', entry.devDependencies]);
  }

  return sections.flatMap(([section, values]) =>
    Object.entries(values ?? {}).map(([name, requirement]) => ({
      name,
      requirement,
      section
    }))
  );
}

export async function readNpmDependencyGraph(
  root: string
): Promise<NpmDependencyGraph> {
  const raw = await readFile(path.join(root, 'package-lock.json'), 'utf8');
  const lockfile = JSON.parse(raw) as PackageLockV2;

  if (!lockfile.packages) {
    throw new Error('Toolip requires package-lock.json lockfileVersion 2 or newer.');
  }

  const identitiesByPath = new Map<string, DependencyIdentity>();

  for (const [installPath, entry] of Object.entries(lockfile.packages)) {
    if (installPath === '' || !entry.version) continue;
    const name = entry.name ?? packageNameFromLockPath(installPath);
    if (!name) continue;

    identitiesByPath.set(installPath, {
      id: identityId(installPath, name, entry.version),
      ecosystem: 'npm',
      name,
      version: entry.version,
      direct: false,
      development: Boolean(entry.dev),
      source: 'package-lock',
      installPath
    });
  }

  const edges: DependencyEdge[] = [];
  const rootTargets = new Set<string>();
  const seenEdges = new Set<string>();

  for (const [fromPath, entry] of Object.entries(lockfile.packages)) {
    const fromIdentity = fromPath === ''
      ? undefined
      : identitiesByPath.get(fromPath);

    if (fromPath !== '' && !fromIdentity) continue;

    for (const requirement of requirements(entry, fromPath === '')) {
      const targetPath = resolveInstalledPath(
        lockfile.packages,
        fromPath,
        requirement.name
      );
      if (!targetPath) continue;

      const target = identitiesByPath.get(targetPath);
      if (!target) continue;

      const from = fromIdentity?.id ?? 'root';
      const key = `${from}:${target.id}:${requirement.section}`;
      if (seenEdges.has(key)) continue;
      seenEdges.add(key);

      edges.push({
        from,
        to: target.id,
        ...requirement
      });

      if (from === 'root') {
        rootTargets.add(target.id);
      }
    }
  }

  const packages = [...identitiesByPath.values()]
    .map((identity) => ({
      ...identity,
      direct: rootTargets.has(identity.id)
    }))
    .sort((a, b) =>
      `${a.name}@${a.version}:${a.installPath}`.localeCompare(
        `${b.name}@${b.version}:${b.installPath}`
      )
    );

  return {
    packages,
    edges: edges.sort((a, b) =>
      `${a.from}:${a.name}:${a.to}`.localeCompare(`${b.from}:${b.name}:${b.to}`)
    ),
    rootDependencies: [...rootTargets].sort()
  };
}

export async function readNpmDependencyInventory(
  root: string
): Promise<DependencyIdentity[]> {
  return (await readNpmDependencyGraph(root)).packages;
}
