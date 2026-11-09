import { readdirSync } from 'node:fs';
import path from 'node:path';
import { lstat } from 'node:fs/promises';
import semver from 'semver';
import { ToolipError } from '../../errors/toolip-error.js';
import {
  readBoundedDependencyText,
  readPnpmDependencyGraph,
  readYarnDependencyGraph
} from './lockfile-resolvers.js';

export type DependencyIdentity = {
  id: string;
  ecosystem: 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'Maven' | 'Packagist';
  manager?: 'npm' | 'pnpm' | 'yarn';
  name: string;
  version: string;
  direct: boolean;
  development: boolean;
  /** Only reachable through optionalDependencies. */
  optional?: boolean;
  /** Lockfile `os` / `cpu` / `libc` constraints (npm allow-list with `!` blocks). */
  os?: string[];
  cpu?: string[];
  libc?: string[];
  source: string;
  /** Distinguishes lock-resolved instances from exact declarations without install evidence. */
  resolutionConfidence?: 'lockfile' | 'declared-pin' | 'workspace' | 'unknown';
  installPath: string;
  integrity?: string;
  resolved?: string;
  registry?: string;
  workspace?: string;
  /** Maven artifact classifier and extension/type from resolved graphs. */
  classifier?: string;
  packageType?: string;
  /** Resolver-specific platform/extra context retained for lock variants. */
  resolutionContext?: string;
  /** Feature names declared in a first-party Cargo manifest, not active resolution. */
  declaredFeatures?: string[];
};

export type DependencyEdge = {
  from: 'root' | string;
  to: string;
  name: string;
  /** Manifest dependency key when it differs from the resolved package name. */
  alias?: string;
  requirement: string;
  section:
    'dependency' | 'devDependency' | 'optionalDependency' | 'peerDependency';
  marker?: string;
  extras?: string[];
  /** Rust/Cargo requested feature flags when declared by a workspace manifest. */
  requestedFeatures?: string[];
  /** Rust/Cargo target cfg expression for a manifest dependency declaration. */
  target?: string;
};

export type UnresolvedDependencyEdge = {
  from: 'root' | string;
  name: string;
  requirement: string;
  section: DependencyEdge['section'];
};

export type DependencyFileSource = Readonly<{
  files: readonly string[];
  hasFile: (relativePath: string) => boolean;
  readText: (relativePath: string) => string | undefined;
}>;

export type NpmDependencyGraph = {
  manager?: 'npm' | 'pnpm' | 'yarn';
  packages: DependencyIdentity[];
  edges: DependencyEdge[];
  unresolvedDependencies: UnresolvedDependencyEdge[];
  rootDependencies: string[];
  complete: boolean;
  warnings: string[];
};

type PackageLockEntry = {
  name?: string;
  version?: string;
  dev?: boolean;
  optional?: boolean;
  os?: string[];
  cpu?: string[];
  libc?: string[];
  link?: boolean;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
};

type PackageLockV2 = {
  lockfileVersion?: number;
  packages?: Record<string, PackageLockEntry>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function validPackageLockEntry(value: unknown): value is PackageLockEntry {
  if (!isRecord(value)) return false;
  for (const field of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies'
  ]) {
    const dependencies = value[field];
    if (
      dependencies !== undefined &&
      (!isRecord(dependencies) ||
        Object.values(dependencies).some(
          (requirement) => typeof requirement !== 'string'
        ))
    )
      return false;
  }
  if (value.peerDependenciesMeta !== undefined) {
    if (!isRecord(value.peerDependenciesMeta)) return false;
    for (const metadata of Object.values(value.peerDependenciesMeta)) {
      if (
        !isRecord(metadata) ||
        (metadata.optional !== undefined &&
          typeof metadata.optional !== 'boolean')
      )
        return false;
    }
  }
  for (const field of ['name', 'version', 'resolved', 'integrity']) {
    if (value[field] !== undefined && typeof value[field] !== 'string')
      return false;
  }
  for (const field of ['dev', 'optional', 'link']) {
    if (value[field] !== undefined && typeof value[field] !== 'boolean')
      return false;
  }
  for (const field of ['os', 'cpu', 'libc']) {
    if (
      value[field] !== undefined &&
      (!Array.isArray(value[field]) ||
        value[field].some((item) => typeof item !== 'string'))
    )
      return false;
  }
  return true;
}

function readCapturedDependencyText(
  fileSource: DependencyFileSource,
  relativePath: string
): string {
  if (!fileSource.hasFile(relativePath)) {
    const error = new Error(
      `Dependency snapshot does not contain ${relativePath}.`
    );
    Object.assign(error, { code: 'ENOENT' });
    throw error;
  }
  const text = fileSource.readText(relativePath);
  if (text === undefined) {
    throw new ToolipError(
      `Dependency snapshot has no text for ${relativePath}.`,
      { code: 'DEPENDENCY_SNAPSHOT_CONTENT_UNAVAILABLE' }
    );
  }
  return text;
}

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

function sanitizedNpmResolution(value: unknown): {
  resolved?: string;
  registry?: string;
} {
  if (typeof value !== 'string' || value.length > 2_048) return {};
  const gitPrefix = value.startsWith('git+') ? 'git+' : '';
  const candidate = gitPrefix ? value.slice(gitPrefix.length) : value;
  try {
    const url = new URL(candidate);
    if (!['https:', 'http:', 'ssh:'].includes(url.protocol)) return {};
    const resolved = `${gitPrefix}${url.protocol}//${url.host}${url.pathname}`;
    if (
      gitPrefix ||
      url.username ||
      url.password ||
      !['https:', 'http:'].includes(url.protocol)
    )
      return { resolved };
    return { resolved, registry: url.origin };
  } catch {
    return {};
  }
}

function parentPackagePath(lockPath: string): string {
  const nestedMarker = '/node_modules/';
  const nestedIndex = lockPath.lastIndexOf(nestedMarker);
  if (nestedIndex !== -1) {
    return lockPath.slice(0, nestedIndex);
  }

  return '';
}

function normalizeResolvedLockPath(resolved: string): string {
  return resolved.replace(/^\.\//, '').replaceAll('\\', '/');
}

function resolveCandidatePath(
  packages: Record<string, PackageLockEntry>,
  candidate: string
): string | undefined {
  const entry = packages[candidate];
  if (entry?.version) {
    return candidate;
  }

  if (entry?.link && entry.resolved) {
    const linkedPath = normalizeResolvedLockPath(entry.resolved);
    if (packages[linkedPath]?.version) {
      return linkedPath;
    }
  }

  return undefined;
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
    const resolved = resolveCandidatePath(packages, candidate);

    if (resolved) {
      return resolved;
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
  optional?: boolean;
}> {
  const sections: Array<{
    section: DependencyEdge['section'];
    values: Record<string, string> | undefined;
  }> = [
    { section: 'dependency', values: entry.dependencies },
    { section: 'optionalDependency', values: entry.optionalDependencies },
    { section: 'peerDependency', values: entry.peerDependencies }
  ];

  if (includeDevelopment) {
    sections.push({ section: 'devDependency', values: entry.devDependencies });
  }

  return sections.flatMap(({ section, values }) =>
    Object.entries(values ?? {}).map(([name, requirement]) => ({
      name,
      requirement,
      section,
      ...(section === 'peerDependency' &&
      entry.peerDependenciesMeta?.[name]?.optional === true
        ? { optional: true }
        : {})
    }))
  );
}

export async function readNpmDependencyGraph(
  root: string,
  fileSource?: DependencyFileSource
): Promise<NpmDependencyGraph> {
  const lockfiles = [
    ['package-lock.json', 'npm'],
    ['pnpm-lock.yaml', 'pnpm'],
    ['yarn.lock', 'yarn']
  ] as const;
  const detected: Array<(typeof lockfiles)[number]> = [];
  if (fileSource) {
    detected.push(...lockfiles.filter(([file]) => fileSource.hasFile(file)));
  } else {
    for (const candidate of lockfiles) {
      const metadata = await lstat(path.join(root, candidate[0])).catch(
        (error: unknown) => {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT')
            return undefined;
          throw error;
        }
      );
      if (metadata) {
        if (!metadata.isFile() || metadata.isSymbolicLink()) {
          throw new ToolipError(
            `Dependency lockfile ${candidate[0]} is not a regular file.`,
            { code: 'DEPENDENCY_LOCKFILE_INVALID' }
          );
        }
        detected.push(candidate);
      }
    }
  }
  if (detected.length > 1) {
    throw new ToolipError(
      `Multiple npm package-manager lockfiles are present (${detected.map(([name]) => name).join(', ')}); dependency identity is ambiguous.`,
      { code: 'DEPENDENCY_LOCKFILE_AMBIGUOUS' }
    );
  }
  const selected = detected[0]?.[1];
  if (selected === 'pnpm') return readPnpmDependencyGraph(root, fileSource);
  if (selected === 'yarn') return readYarnDependencyGraph(root, fileSource);

  const raw = fileSource
    ? readCapturedDependencyText(fileSource, 'package-lock.json')
    : await readBoundedDependencyText(path.join(root, 'package-lock.json'));
  const parsed: unknown = JSON.parse(raw);

  if (
    !isRecord(parsed) ||
    ![2, 3].includes(parsed.lockfileVersion as number) ||
    !isRecord(parsed.packages)
  ) {
    throw new Error(
      'Toolip requires a package-lock.json lockfileVersion 2 or 3 with a packages object.'
    );
  }

  const lockfile = parsed as PackageLockV2;
  const warnings: string[] = [];
  const packageLockEntries = Object.create(null) as Record<
    string,
    PackageLockEntry
  >;
  for (const [installPath, entry] of Object.entries(lockfile.packages ?? {})) {
    if (!validPackageLockEntry(entry)) {
      warnings.push('npm-lockfile-package-entry-invalid');
      continue;
    }
    packageLockEntries[installPath] = entry;
  }

  const identitiesByPath = new Map<string, DependencyIdentity>();

  for (const [installPath, entry] of Object.entries(packageLockEntries)) {
    if (installPath === '') continue;
    if (!entry.version) {
      if (!entry.link) warnings.push('npm-lockfile-version-unresolved');
      else if (!entry.resolved)
        warnings.push('npm-lockfile-link-target-unresolved');
      continue;
    }
    if (
      path.posix.isAbsolute(installPath) ||
      /^[A-Za-z]:/u.test(installPath) ||
      installPath.includes('\\') ||
      installPath.includes('\0') ||
      installPath.split('/').includes('..')
    ) {
      warnings.push('npm-lockfile-install-path-invalid');
      continue;
    }
    if (!semver.valid(entry.version)) {
      warnings.push('npm-lockfile-version-unresolved');
      continue;
    }
    const name = entry.name ?? packageNameFromLockPath(installPath);
    if (!name) {
      warnings.push('npm-lockfile-package-name-unresolved');
      continue;
    }
    const resolution = sanitizedNpmResolution(entry.resolved);

    identitiesByPath.set(installPath, {
      id: identityId(installPath, name, entry.version),
      ecosystem: 'npm',
      name,
      version: entry.version,
      direct: false,
      development: Boolean(entry.dev),
      optional: entry.optional === true ? true : undefined,
      os: Array.isArray(entry.os) ? entry.os.map(String) : undefined,
      cpu: Array.isArray(entry.cpu) ? entry.cpu.map(String) : undefined,
      libc: Array.isArray(entry.libc) ? entry.libc.map(String) : undefined,
      source: 'package-lock',
      resolutionConfidence: 'lockfile',
      installPath,
      workspace: !installPath.startsWith('node_modules/')
        ? installPath
        : undefined,
      manager: 'npm',
      integrity: entry.integrity,
      ...(resolution.resolved ? { resolved: resolution.resolved } : {}),
      ...(resolution.registry ? { registry: resolution.registry } : {})
    });
  }

  const edges: DependencyEdge[] = [];
  const unresolvedDependencies: UnresolvedDependencyEdge[] = [];
  const rootTargets = new Set<string>();
  const seenEdges = new Set<string>();
  for (const [fromPath, entry] of Object.entries(packageLockEntries)) {
    const fromIdentity =
      fromPath === '' ? undefined : identitiesByPath.get(fromPath);

    if (fromPath !== '' && !fromIdentity) continue;

    for (const requirement of requirements(entry, fromPath === '')) {
      const targetPath = resolveInstalledPath(
        packageLockEntries,
        fromPath,
        requirement.name
      );
      if (!targetPath) {
        if (requirement.optional) continue;
        unresolvedDependencies.push({
          from: fromIdentity?.id ?? 'root',
          name: requirement.name,
          requirement: requirement.requirement,
          section: requirement.section
        });
        warnings.push(
          `unresolved npm dependency ${requirement.name}@${requirement.requirement} from ${fromPath || 'root'}`
        );
        continue;
      }

      const target = identitiesByPath.get(targetPath);
      if (!target) {
        unresolvedDependencies.push({
          from: fromIdentity?.id ?? 'root',
          name: requirement.name,
          requirement: requirement.requirement,
          section: requirement.section
        });
        warnings.push(
          `unresolved npm package identity ${requirement.name}@${requirement.requirement} from ${fromPath || 'root'}`
        );
        continue;
      }

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
    manager: 'npm',
    packages,
    edges: edges.sort((a, b) =>
      `${a.from}:${a.name}:${a.to}`.localeCompare(`${b.from}:${b.name}:${b.to}`)
    ),
    unresolvedDependencies,
    rootDependencies: [...rootTargets].sort(),
    complete: warnings.length === 0,
    warnings: [...new Set(warnings)].sort()
  };
}

export async function readNpmDependencyInventory(
  root: string,
  fileSource?: DependencyFileSource
): Promise<DependencyIdentity[]> {
  const graph = await readNpmDependencyGraph(root, fileSource);
  if (!graph.complete) {
    throw new ToolipError(
      `Dependency inventory is incomplete: ${graph.warnings.slice(0, 5).join('; ')}`,
      { code: 'DEPENDENCY_INVENTORY_INCOMPLETE' }
    );
  }
  return graph.packages;
}

function allowedBy(constraint: string[] | undefined, current: string): boolean {
  if (!constraint || constraint.length === 0) return true;
  if (constraint.includes(`!${current}`)) return false;
  const allow = constraint.filter((entry) => !entry.startsWith('!'));
  return allow.length === 0 || allow.includes(current);
}

type RuntimeLibc = 'glibc' | 'musl' | 'unknown';

/** Use positive runtime evidence; unknown libc cannot exclude a package. */
function detectRuntimeLibc(): RuntimeLibc {
  if (process.platform !== 'linux') return 'unknown';
  try {
    const report = process.report.getReport() as {
      header?: { glibcVersionRuntime?: string };
    };
    if (report.header?.glibcVersionRuntime) return 'glibc';
  } catch {
    // Runtime reports are not available on all Node distributions.
  }
  try {
    if (
      readdirSync('/lib').some(
        (name) => name.startsWith('ld-musl-') && name.endsWith('.so.1')
      )
    ) {
      return 'musl';
    }
  } catch {
    // Minimal containers may not expose the musl loader directory.
  }
  return 'unknown';
}

const currentLibc = detectRuntimeLibc();

/**
 * True only when lockfile `os`/`cpu`/`libc` constraints prove an optional
 * package is not applicable. Unknown libc never proves a package is omitted.
 */
export function isOmittedOnPlatform(
  dependency: Pick<DependencyIdentity, 'optional' | 'os' | 'cpu' | 'libc'>,
  platform: string = process.platform,
  arch: string = process.arch,
  libc: RuntimeLibc = currentLibc
): boolean {
  if (!dependency.optional) return false;
  return (
    !allowedBy(dependency.os, platform) ||
    !allowedBy(dependency.cpu, arch) ||
    (platform === 'linux' &&
      libc !== 'unknown' &&
      !allowedBy(dependency.libc, libc))
  );
}
