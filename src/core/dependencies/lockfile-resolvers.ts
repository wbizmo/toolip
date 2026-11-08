import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import fg from 'fast-glob';
import semver from 'semver';
import { parseDocument } from 'yaml';
import type {
  DependencyEdge,
  DependencyFileSource,
  DependencyIdentity,
  NpmDependencyGraph,
  UnresolvedDependencyEdge
} from './inventory.js';

type RecordValue = Record<string, unknown>;
type LockedInstance = {
  locator: string;
  name: string;
  version: string;
  installPath: string;
  integrity?: string;
  resolved?: string;
  dev?: boolean;
  optional?: boolean;
  workspace?: string;
  resolutionContext?: string;
  dependencies?: RecordValue;
  optionalDependencies?: RecordValue;
  peerDependencies?: RecordValue;
};

type WorkspaceManifestBudget = { count: number; bytes: number };
const maximumWorkspaceManifests = 10_000;
const maximumWorkspaceManifestBytes = 1_048_576;
const maximumWorkspaceManifestTotalBytes = 32 * 1024 * 1024;
const maximumYarnResolverCandidateWork = 250_000;

function record(value: unknown): RecordValue | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as RecordValue)
    : undefined;
}

function safeResolved(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 2_048) return undefined;
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol)) return undefined;
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return undefined;
  }
}

function packageIdentity(
  manager: 'pnpm' | 'yarn',
  item: LockedInstance,
  direct: boolean,
  development = false
): DependencyIdentity {
  return {
    id: `${manager}:${item.locator}`,
    ecosystem: 'npm',
    manager,
    name: item.name,
    version: item.version,
    direct,
    development: development || item.dev === true,
    optional: item.optional ? true : undefined,
    integrity: item.integrity,
    resolved: item.resolved,
    registry: item.resolved ? new URL(item.resolved).origin : undefined,
    source: manager === 'pnpm' ? 'pnpm-lock.yaml' : 'yarn.lock',
    installPath: item.installPath,
    workspace: item.workspace,
    resolutionContext: item.resolutionContext
  };
}

function parsePnpmLocator(locator: string):
  | {
      name: string;
      version: string;
      suffix: string;
    }
  | undefined {
  const clean = locator.replace(/^\//u, '');
  const separator = clean.startsWith('@')
    ? clean.indexOf('@', clean.indexOf('/') + 1)
    : clean.indexOf('@');
  let name = '';
  let versionPart = '';
  if (separator > 0) {
    name = clean.slice(0, separator);
    versionPart = clean.slice(separator + 1);
  } else {
    const parts = clean.split('/');
    const versionIndex = clean.startsWith('@') ? 2 : 1;
    if (parts.length <= versionIndex) return undefined;
    name = parts.slice(0, versionIndex).join('/');
    versionPart = parts.slice(versionIndex).join('/');
  }
  const marker = versionPart.search(/[(_]/u);
  const version = (
    marker < 0 ? versionPart : versionPart.slice(0, marker)
  ).replace(/^v/u, '');
  if (!name || !semver.valid(version)) return undefined;
  return {
    name,
    version,
    suffix: marker < 0 ? '' : versionPart.slice(marker)
  };
}

function pnpmStorePath(locator: string, name: string): string {
  const parsed = parsePnpmLocator(locator);
  const base = name.replaceAll('/', '+');
  const peer = parsed?.suffix
    ? parsed.suffix.startsWith('_')
      ? parsed.suffix.replaceAll('/', '+')
      : `_${parsed.suffix.replace(/[()]/gu, '').replaceAll('/', '+')}`
    : '';
  const version = parsed?.version ?? 'unknown';
  return `node_modules/.pnpm/${base}@${version}${peer}/node_modules/${name}`;
}

function pnpmRequirementKey(requested: string): {
  version: string;
  suffix: string;
} {
  const clean = requested.replace(/^v/u, '');
  const marker = clean.search(/[(_]/u);
  const version = marker < 0 ? clean : clean.slice(0, marker);
  const suffix = marker < 0 ? '' : clean.slice(marker);
  return { version, suffix };
}

function makeGraph(
  manager: 'pnpm' | 'yarn',
  instances: LockedInstance[],
  edgeSpecs: Array<{
    from: string;
    target?: LockedInstance;
    name: string;
    requirement: string;
    section: DependencyEdge['section'];
  }>,
  warnings: string[]
): NpmDependencyGraph {
  const directIds = new Set<string>();
  const edges: DependencyEdge[] = [];
  const unresolvedDependencies: UnresolvedDependencyEdge[] = [];
  for (const spec of edgeSpecs) {
    if (!spec.target) {
      unresolvedDependencies.push({
        from: spec.from,
        name: spec.name,
        requirement: spec.requirement,
        section: spec.section
      });
      warnings.push(
        `unresolved ${manager} dependency ${spec.name}@${spec.requirement} from ${spec.from}`
      );
      continue;
    }
    const to = `${manager}:${spec.target.locator}`;
    edges.push({
      from: spec.from,
      to,
      name: spec.name,
      requirement: spec.requirement,
      section: spec.section
    });
    if (spec.from === 'root') directIds.add(to);
  }
  const packages = instances
    .map((item) =>
      packageIdentity(
        manager,
        item,
        directIds.has(`${manager}:${item.locator}`)
      )
    )
    .sort((a, b) =>
      `${a.name}@${a.version}:${a.installPath}`.localeCompare(
        `${b.name}@${b.version}:${b.installPath}`
      )
    );
  const packageIds = new Set(packages.map((item) => item.id));
  const validEdges = [
    ...new Map(
      edges
        .filter((edge) => edge.from === 'root' || packageIds.has(edge.from))
        .filter((edge) => packageIds.has(edge.to))
        .map((edge) => [
          `${edge.from}\0${edge.to}\0${edge.name}\0${edge.requirement}\0${edge.section}`,
          edge
        ])
    ).values()
  ];
  return {
    manager,
    packages,
    edges: validEdges.sort((a, b) =>
      `${a.from}:${a.name}:${a.to}`.localeCompare(`${b.from}:${b.name}:${b.to}`)
    ),
    unresolvedDependencies,
    rootDependencies: [...directIds].sort(),
    complete: warnings.length === 0,
    warnings: [...new Set(warnings)].sort()
  };
}

function parseSections(
  sections: RecordValue,
  resolve: (name: string, requirement: string) => LockedInstance | undefined,
  from: string,
  includeDevelopment: boolean,
  resolveRaw?: (name: string, raw: unknown) => LockedInstance | undefined
): Array<{
  from: string;
  target?: LockedInstance;
  name: string;
  requirement: string;
  section: DependencyEdge['section'];
}> {
  const result: Array<{
    from: string;
    target?: LockedInstance;
    name: string;
    requirement: string;
    section: DependencyEdge['section'];
  }> = [];
  const fields: ReadonlyArray<readonly [string, DependencyEdge['section']]> = [
    ['dependencies', 'dependency'],
    ['optionalDependencies', 'optionalDependency'],
    ['peerDependencies', 'peerDependency'],
    ...(includeDevelopment
      ? [['devDependencies', 'devDependency'] as const]
      : [])
  ];
  for (const [field, section] of fields) {
    const values = record(sections[field]);
    for (const [name, raw] of Object.entries(values ?? {})) {
      const details = record(raw);
      const requirement =
        typeof details?.specifier === 'string'
          ? details.specifier
          : typeof raw === 'string'
            ? raw
            : typeof details?.version === 'string'
              ? details.version
              : undefined;
      if (!requirement) continue;
      const resolveRequirement =
        typeof raw === 'string'
          ? raw
          : typeof details?.version === 'string'
            ? details.version
            : requirement;
      result.push({
        from,
        target: resolveRaw
          ? resolveRaw(name, raw)
          : resolve(name, resolveRequirement),
        name,
        requirement,
        section
      });
    }
  }
  return result;
}

/** Resolves pnpm v6-v9 lockfiles without coercing ranges into installed versions. */
export async function readPnpmDependencyGraph(
  root: string,
  fileSource?: DependencyFileSource
): Promise<NpmDependencyGraph> {
  const lockText = fileSource
    ? readCapturedText(fileSource, 'pnpm-lock.yaml')
    : await readBoundedText(path.join(root, 'pnpm-lock.yaml'));
  const document = parseDocument(lockText, {
    uniqueKeys: true,
    prettyErrors: false
  });
  if (document.errors.length)
    throw new Error('pnpm lockfile is malformed or has duplicate keys');
  const lock = record(document.toJS());
  const packageMap = record(lock?.packages);
  if (!lock || !packageMap)
    throw new Error('pnpm lockfile has no supported packages map');
  if (!/^[6-9](?:\.\d+)?$/u.test(String(lock.lockfileVersion ?? '')))
    throw new Error('pnpm lockfile version is unsupported');
  const warnings: string[] = [];
  const instances: LockedInstance[] = [];
  const byNameAndVersion = new Map<string, LockedInstance[]>();
  const byNameVersionAndSuffix = new Map<string, LockedInstance[]>();
  const packageEntries = Object.entries(packageMap).flatMap(
    ([locator, raw]) => {
      const parsed = parsePnpmLocator(locator);
      if (!parsed) {
        warnings.push(
          `unsupported pnpm package locator ${locator.slice(0, 200)}`
        );
        return [];
      }
      const entry = record(raw);
      if (!entry) {
        warnings.push(
          `pnpm package metadata is malformed: ${locator.slice(0, 200)}`
        );
        return [];
      }
      return [{ locator, entry, parsed }];
    }
  );
  const packageEntriesByLocator = new Map(
    packageEntries.map((item) => [item.locator, item])
  );
  const packageEntriesByNameVersion = new Map<string, typeof packageEntries>();
  const packageEntriesByNameVersionSuffix = new Map<
    string,
    typeof packageEntries
  >();
  for (const item of packageEntries) {
    const versionKey = JSON.stringify([item.parsed.name, item.parsed.version]);
    const versionEntries = packageEntriesByNameVersion.get(versionKey) ?? [];
    versionEntries.push(item);
    packageEntriesByNameVersion.set(versionKey, versionEntries);
    const suffixKey = JSON.stringify([
      item.parsed.name,
      item.parsed.version,
      item.parsed.suffix
    ]);
    const suffixEntries =
      packageEntriesByNameVersionSuffix.get(suffixKey) ?? [];
    suffixEntries.push(item);
    packageEntriesByNameVersionSuffix.set(suffixKey, suffixEntries);
  }
  const snapshots = record(lock.snapshots) ?? {};
  const usesSnapshotGraph =
    Number.parseInt(String(lock.lockfileVersion), 10) >= 9;
  const installedEntries = usesSnapshotGraph
    ? Object.entries(snapshots)
        .map(([locator, snapshot]) => {
          const parsed = parsePnpmLocator(locator);
          if (!parsed) {
            warnings.push(
              `unsupported pnpm snapshot locator ${locator.slice(0, 200)}`
            );
            return undefined;
          }
          const snapshotEntry = record(snapshot);
          if (!snapshotEntry) {
            warnings.push(
              `pnpm snapshot record is malformed: ${locator.slice(0, 200)}`
            );
            return undefined;
          }
          const versionKey = JSON.stringify([parsed.name, parsed.version]);
          const candidates = packageEntriesByNameVersion.get(versionKey) ?? [];
          const suffixCandidates =
            packageEntriesByNameVersionSuffix.get(
              JSON.stringify([parsed.name, parsed.version, parsed.suffix])
            ) ?? [];
          const metadata =
            packageEntriesByLocator.get(locator) ??
            (suffixCandidates.length === 1 ? suffixCandidates[0] : undefined) ??
            (candidates.length === 1 ? candidates[0] : undefined);
          if (!metadata) {
            warnings.push(
              `pnpm snapshot has no unique package metadata: ${locator.slice(0, 200)}`
            );
            return undefined;
          }
          return {
            locator,
            parsed,
            entry: metadata.entry,
            snapshot: snapshotEntry
          };
        })
        .filter((item): item is NonNullable<typeof item> => item !== undefined)
    : packageEntries.map(({ locator, entry, parsed }) => ({
        locator,
        entry,
        parsed,
        snapshot: entry
      }));
  for (const { locator, entry, parsed, snapshot } of installedEntries) {
    const resolution = record(entry.resolution);
    const item: LockedInstance = {
      locator,
      name: parsed.name,
      version: parsed.version,
      installPath: pnpmStorePath(locator, parsed.name),
      integrity:
        typeof resolution?.integrity === 'string'
          ? resolution.integrity.slice(0, 1_024)
          : undefined,
      resolved: safeResolved(resolution?.tarball),
      dev: entry.dev === true,
      optional: entry.optional === true,
      dependencies: record(snapshot.dependencies) ?? record(entry.dependencies),
      optionalDependencies:
        record(snapshot.optionalDependencies) ??
        record(entry.optionalDependencies)
    };
    instances.push(item);
    const versionKey = JSON.stringify([item.name, item.version]);
    const versionSiblings = byNameAndVersion.get(versionKey) ?? [];
    versionSiblings.push(item);
    byNameAndVersion.set(versionKey, versionSiblings);
    const parsedLocator = parsePnpmLocator(item.locator);
    if (parsedLocator) {
      const suffixKey = JSON.stringify([
        item.name,
        parsedLocator.version,
        parsedLocator.suffix
      ]);
      const suffixSiblings = byNameVersionAndSuffix.get(suffixKey) ?? [];
      suffixSiblings.push(item);
      byNameVersionAndSuffix.set(suffixKey, suffixSiblings);
    }
  }
  const edgeSpecs = [] as Parameters<typeof makeGraph>[2];
  const resolve = (
    name: string,
    requirement: string
  ): LockedInstance | undefined => {
    // pnpm records npm aliases under the target package locator, while the
    // importer dependency key remains the alias. Resolve the lockfile's exact
    // target identity before falling back to the requested package name.
    const target = parsePnpmLocator(requirement.replace(/^npm:/u, ''));
    if (target) {
      const exact =
        byNameVersionAndSuffix.get(
          JSON.stringify([target.name, target.version, target.suffix])
        ) ?? [];
      if (exact.length === 1) return exact[0];
    }
    const parsed = pnpmRequirementKey(requirement.replace(/^npm:/u, ''));
    if (parsed.suffix) {
      const matches =
        byNameVersionAndSuffix.get(
          JSON.stringify([name, parsed.version, parsed.suffix])
        ) ?? [];
      return matches.length === 1 ? matches[0] : undefined;
    }
    const matches =
      byNameAndVersion.get(JSON.stringify([name, parsed.version])) ?? [];
    return matches.length === 1 ? matches[0] : undefined;
  };
  const importers = record(lock.importers) ?? {};
  const workspaceByPath = new Map<string, LockedInstance>();
  const workspaceByName = new Map<string, LockedInstance>();
  const workspaceCandidates = new Map<string, LockedInstance[]>();
  const workspaceManifestBudget: WorkspaceManifestBudget = {
    count: 0,
    bytes: 0
  };
  const importerPaths = Object.keys(importers).filter((item) => item !== '.');
  if (importerPaths.length > maximumWorkspaceManifests) {
    warnings.push('pnpm workspace importer count exceeds the configured limit');
  }
  for (const importerPath of importerPaths.slice(
    0,
    maximumWorkspaceManifests
  )) {
    if (importerPath === '.') continue;
    const normalized = normalizeWorkspacePath(importerPath);
    const manifest = normalized
      ? await readWorkspaceManifest(
          root,
          normalized,
          fileSource,
          workspaceManifestBudget
        ).catch(() => undefined)
      : undefined;
    if (
      !normalized ||
      !manifest ||
      typeof manifest.name !== 'string' ||
      typeof manifest.version !== 'string' ||
      !semver.valid(manifest.version)
    ) {
      warnings.push(
        `pnpm workspace importer has no valid package identity: ${importerPath.slice(0, 200)}`
      );
      continue;
    }
    const item: LockedInstance = {
      locator: `workspace:${normalized}`,
      name: manifest.name,
      version: manifest.version,
      installPath: normalized,
      workspace: normalized,
      dev: true
    };
    workspaceByPath.set(normalized, item);
    const candidates = workspaceCandidates.get(item.name) ?? [];
    candidates.push(item);
    workspaceCandidates.set(item.name, candidates);
  }
  for (const [name, candidates] of workspaceCandidates) {
    if (candidates.length === 1 && candidates[0])
      workspaceByName.set(name, candidates[0]);
    else
      warnings.push(
        `pnpm workspace package name is ambiguous: ${name.slice(0, 200)}`
      );
  }
  const resolveImporterDependency =
    (importerPath: string) => (name: string, raw: unknown) => {
      const details = record(raw);
      const resolved =
        typeof raw === 'string' ? raw : String(details?.version ?? '');
      if (resolved.startsWith('link:')) {
        const linkedPath = normalizeWorkspacePath(
          path.posix.join(
            importerPath === '.' ? '' : importerPath,
            resolved.slice(5)
          )
        );
        return linkedPath ? workspaceByPath.get(linkedPath) : undefined;
      }
      if (resolved.startsWith('workspace:')) return workspaceByName.get(name);
      return resolve(name, resolved || String(details?.specifier ?? ''));
    };
  const rootImporter = record(importers['.']);
  if (!rootImporter) warnings.push('pnpm lockfile has no root importer');
  if (rootImporter)
    edgeSpecs.push(
      ...parseSections(
        rootImporter,
        resolve,
        'root',
        true,
        resolveImporterDependency('.')
      )
    );
  for (const [importerPath, rawImporter] of Object.entries(importers)) {
    if (importerPath === '.') continue;
    const normalized = normalizeWorkspacePath(importerPath);
    const workspace = normalized ? workspaceByPath.get(normalized) : undefined;
    if (!workspace) continue;
    edgeSpecs.push(
      ...parseSections(
        record(rawImporter) ?? {},
        resolve,
        `pnpm:${workspace.locator}`,
        true,
        resolveImporterDependency(importerPath)
      )
    );
  }
  for (const item of instances) {
    edgeSpecs.push(
      ...parseSections(item, resolve, `pnpm:${item.locator}`, false)
    );
  }
  return makeGraph(
    'pnpm',
    [...instances, ...workspaceByPath.values()],
    edgeSpecs,
    warnings
  );
}

function normalizeWorkspacePath(value: string): string | undefined {
  const normalized = path.posix.normalize(value.replaceAll('\\', '/'));
  if (
    normalized === '.' ||
    normalized.startsWith('../') ||
    path.posix.isAbsolute(normalized) ||
    normalized.includes('\0')
  )
    return undefined;
  return normalized;
}

async function readWorkspaceManifest(
  root: string,
  relative: string,
  fileSource: DependencyFileSource | undefined,
  budget: WorkspaceManifestBudget
): Promise<RecordValue | undefined> {
  const normalized = normalizeWorkspacePath(relative);
  if (!normalized) return undefined;
  if (
    budget.count >= maximumWorkspaceManifests ||
    budget.bytes >= maximumWorkspaceManifestTotalBytes
  )
    throw new Error('workspace manifest budget exceeded');
  const maximumBytes = Math.min(
    maximumWorkspaceManifestBytes,
    maximumWorkspaceManifestTotalBytes - budget.bytes
  );
  let text: string;
  if (fileSource) {
    const manifestPath = `${normalized}/package.json`;
    if (!fileSource.hasFile(manifestPath)) return undefined;
    const captured = fileSource.readText(manifestPath);
    if (captured === undefined) return undefined;
    text = captured;
  } else {
    const rootPath = await realpath(root);
    const segments = normalized.split('/');
    let current = rootPath;
    for (const segment of segments) {
      current = path.join(current, segment);
      const metadata = await lstat(current);
      if (!metadata.isDirectory() || metadata.isSymbolicLink())
        return undefined;
    }
    text = await readBoundedDependencyText(
      path.join(current, 'package.json'),
      maximumBytes
    );
  }
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > maximumBytes)
    throw new Error('workspace manifest exceeds the aggregate read budget');
  budget.count++;
  budget.bytes += bytes;
  return record(JSON.parse(text));
}

function splitYarnSelectors(header: string): string[] {
  const values: string[] = [];
  let quoted = false;
  let escaped = false;
  let start = 0;
  for (let index = 0; index < header.length; index++) {
    const char = header[index] ?? '';
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (char === ',' && !quoted) {
      values.push(header.slice(start, index).trim().replace(/^"|"$/gu, ''));
      start = index + 1;
    }
  }
  values.push(header.slice(start).trim().replace(/^"|"$/gu, ''));
  return values.filter(Boolean);
}

function parseYarnClassic(source: string): RecordValue {
  const entries: RecordValue = {};
  let selectors: string[] = [];
  let entry: RecordValue = {};
  let activeSection = '';
  const flush = (): void => {
    for (const selector of selectors) {
      if (Object.hasOwn(entries, selector))
        throw new Error('Yarn classic lockfile has duplicate descriptors');
      entries[selector] = entry;
    }
    selectors = [];
    entry = {};
    activeSection = '';
  };
  for (const line of source.split(/\r?\n/u)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (!/^\s/u.test(line)) {
      if (!line.endsWith(':'))
        throw new Error('Yarn classic lockfile contains an invalid entry');
      flush();
      selectors = splitYarnSelectors(line.slice(0, -1));
      if (
        selectors.length === 0 ||
        new Set(selectors).size !== selectors.length
      )
        throw new Error('Yarn classic lockfile has invalid descriptors');
      continue;
    }
    const top = line.match(
      /^ {2}([A-Za-z][A-Za-z0-9]*):?(?:\s+(?:"((?:\\.|[^"])*)"|([^\s]+)))?\s*$/u
    );
    if (top?.[1]) {
      activeSection =
        top[1] === 'dependencies' || top[1] === 'optionalDependencies'
          ? top[1]
          : '';
      const value =
        top[2] !== undefined ? top[2].replace(/\\([\\"])/gu, '$1') : top[3];
      if (value !== undefined) entry[top[1]] = value;
      else if (activeSection) entry[activeSection] = {};
      continue;
    }
    const child = line.match(/^ {4}([^\s]+)\s+"([^"]*)"\s*$/u);
    if (child?.[1] && child[2] !== undefined && activeSection) {
      const section = record(entry[activeSection]) ?? {};
      section[child[1]] = child[2];
      entry[activeSection] = section;
      continue;
    }
    throw new Error('Yarn classic lockfile contains an unsupported record');
  }
  flush();
  return entries;
}

function yarnDescriptorName(
  descriptor: string
): { name: string; selector: string } | undefined {
  const berry = descriptor.indexOf('@npm:');
  if (berry > 0)
    return {
      name: descriptor.slice(0, berry),
      selector: descriptor.slice(berry + 1)
    };
  const separator = descriptor.startsWith('@')
    ? descriptor.indexOf('@', descriptor.indexOf('/') + 1)
    : descriptor.indexOf('@');
  if (separator < 1) return undefined;
  return {
    name: descriptor.slice(0, separator),
    selector: descriptor.slice(separator + 1)
  };
}

async function readYarnWorkspaces(
  root: string,
  manifest: RecordValue,
  warnings: string[],
  fileSource?: DependencyFileSource
): Promise<LockedInstance[]> {
  const rawWorkspaces = Array.isArray(manifest.workspaces)
    ? manifest.workspaces
    : record(manifest.workspaces)?.packages;
  if (!Array.isArray(rawWorkspaces)) return [];
  const patterns = rawWorkspaces.filter(
    (value): value is string => typeof value === 'string'
  );
  if (patterns.length !== rawWorkspaces.length || patterns.length > 256) {
    warnings.push(
      'Yarn workspaces has malformed or excessive package patterns'
    );
  }
  const safePatterns = patterns
    .filter((pattern) => {
      const normalized = pattern.replaceAll('\\', '/');
      const safe =
        !path.posix.isAbsolute(normalized) &&
        !normalized.split('/').includes('..') &&
        !normalized.includes('\0');
      if (!safe)
        warnings.push(
          `unsafe Yarn workspace pattern: ${pattern.slice(0, 160)}`
        );
      return safe;
    })
    .slice(0, 256);
  const matched = fileSource
    ? snapshotWorkspaceDirectories(fileSource.files, safePatterns, warnings)
    : await streamYarnWorkspaceDirectories(root, safePatterns, warnings);
  if (matched.length > 10_000)
    warnings.push(
      'Yarn workspace discovery exceeded the 10000-directory limit'
    );
  const result: LockedInstance[] = [];
  const seenNames = new Set<string>();
  const workspaceManifestBudget: WorkspaceManifestBudget = {
    count: 0,
    bytes: 0
  };
  for (const relative of matched.slice(0, 10_000).sort()) {
    if (
      workspaceManifestBudget.count >= maximumWorkspaceManifests ||
      workspaceManifestBudget.bytes >= maximumWorkspaceManifestTotalBytes
    ) {
      warnings.push('Yarn workspace manifest read budget exceeded');
      break;
    }
    const normalized = normalizeWorkspacePath(relative);
    const workspace = normalized
      ? await readWorkspaceManifest(
          root,
          normalized,
          fileSource,
          workspaceManifestBudget
        ).catch(() => undefined)
      : undefined;
    if (
      !normalized ||
      !workspace ||
      typeof workspace.name !== 'string' ||
      typeof workspace.version !== 'string' ||
      !semver.valid(workspace.version)
    ) {
      warnings.push(
        `Yarn workspace has no valid package identity: ${relative.slice(0, 200)}`
      );
      continue;
    }
    if (seenNames.has(workspace.name)) {
      warnings.push(
        `Yarn workspace package name is ambiguous: ${workspace.name.slice(0, 200)}`
      );
    }
    seenNames.add(workspace.name);
    result.push({
      locator: `workspace:${normalized}`,
      name: workspace.name,
      version: workspace.version,
      installPath: normalized,
      workspace: normalized,
      resolutionContext: `workspace:${normalized}`,
      dependencies: workspace
    });
  }
  return result;
}

/** Streams glob matches so workspace discovery cannot materialize an unbounded result list. */
async function streamYarnWorkspaceDirectories(
  root: string,
  patterns: readonly string[],
  warnings: string[]
): Promise<string[]> {
  const maximumDirectories = 10_000;
  const stream = fg.stream(
    patterns.map((pattern) => `${pattern.replace(/\/$/u, '')}/package.json`),
    {
      cwd: root,
      absolute: false,
      onlyFiles: true,
      unique: true,
      followSymbolicLinks: false,
      ignore: [
        '.git/**',
        'node_modules/**',
        '**/node_modules/**',
        '**/.yarn/**'
      ]
    }
  ) as unknown as AsyncIterable<string | { path: string }> & {
    destroy?: () => void;
  };
  const directories = new Set<string>();
  for await (const item of stream) {
    const manifestPath = typeof item === 'string' ? item : item.path;
    if (!manifestPath.endsWith('/package.json')) continue;
    const directory = manifestPath.slice(0, -'/package.json'.length);
    if (!directory) continue;
    directories.add(directory);
    if (directories.size > maximumDirectories) {
      warnings.push(
        `Yarn workspace discovery exceeded the ${maximumDirectories}-directory limit`
      );
      stream.destroy?.();
      break;
    }
  }
  return [...directories].sort().slice(0, maximumDirectories);
}

function workspacePatternRegex(pattern: string): RegExp | undefined {
  let source = '^';
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index] ?? '';
    const next = pattern[index + 1] ?? '';
    if (char === '*' && next === '*') {
      index += 1;
      if (pattern[index + 1] === '/') {
        index += 1;
        source += '(?:.*/)?';
      } else {
        source += '.*';
      }
    } else if (char === '*') {
      source += '[^/]*';
    } else if (char === '?') {
      source += '[^/]';
    } else if ('{}[]()!+'.includes(char)) {
      return undefined;
    } else {
      source += char.replace(/[|\\^$.*+?()[\]{}]/gu, '\\$&');
    }
  }
  return new RegExp(`${source}$`, 'u');
}

function snapshotWorkspaceDirectories(
  files: readonly string[],
  patterns: readonly string[],
  warnings: string[]
): string[] {
  const positive = patterns.filter((pattern) => !pattern.startsWith('!'));
  const negative = patterns
    .filter((pattern) => pattern.startsWith('!'))
    .map((pattern) => pattern.slice(1));
  const positiveRegex = positive.map(
    (pattern) => [pattern, workspacePatternRegex(pattern)] as const
  );
  const negativeRegex = negative.map(
    (pattern) => [pattern, workspacePatternRegex(pattern)] as const
  );
  for (const [pattern, matcher] of [...positiveRegex, ...negativeRegex]) {
    if (!matcher)
      warnings.push(
        `unsupported Yarn workspace pattern in snapshot: ${pattern.slice(0, 160)}`
      );
  }
  const directories = new Set<string>();
  for (const file of files) {
    if (!file.endsWith('/package.json')) continue;
    const directory = file.slice(0, -'/package.json'.length);
    if (directory) directories.add(directory);
  }
  return [...directories]
    .filter((directory) =>
      positiveRegex.some(([, matcher]) => matcher?.test(directory))
    )
    .filter(
      (directory) =>
        !negativeRegex.some(([, matcher]) => matcher?.test(directory))
    )
    .sort();
}

/** Resolves Yarn classic and Berry lock entries; PnP gets stable virtual instance paths. */
export async function readYarnDependencyGraph(
  root: string,
  fileSource?: DependencyFileSource
): Promise<NpmDependencyGraph> {
  const lockText = fileSource
    ? readCapturedText(fileSource, 'yarn.lock')
    : await readBoundedText(path.join(root, 'yarn.lock'));
  let lock: RecordValue;
  const classic = /^#\s*yarn lockfile v1/mu.test(lockText);
  if (classic) {
    lock = parseYarnClassic(lockText);
  } else {
    const document = parseDocument(lockText, {
      uniqueKeys: true,
      prettyErrors: false
    });
    if (document.errors.length)
      throw new Error('Yarn lockfile is malformed or has duplicate keys');
    lock = record(document.toJS()) ?? {};
    const metadata = record(lock.__metadata);
    if (
      !metadata ||
      !Number.isSafeInteger(metadata.version) ||
      Number(metadata.version) < 1
    )
      throw new Error('Yarn Berry lockfile metadata is missing or invalid');
  }
  const warnings: string[] = [];
  const manifest = record(
    JSON.parse(
      fileSource
        ? readCapturedText(fileSource, 'package.json')
        : await readBoundedText(path.join(root, 'package.json'))
    )
  );
  if (!manifest) throw new Error('root package manifest is malformed');
  const workspaces = await readYarnWorkspaces(
    root,
    manifest,
    warnings,
    fileSource
  );
  const workspacesByName = new Map<string, LockedInstance>();
  const workspacesByNameCandidates = new Map<string, LockedInstance[]>();
  for (const item of workspaces) {
    const matches = workspacesByNameCandidates.get(item.name) ?? [];
    matches.push(item);
    workspacesByNameCandidates.set(item.name, matches);
  }
  for (const [name, matches] of workspacesByNameCandidates) {
    if (matches.length === 1 && matches[0])
      workspacesByName.set(name, matches[0]);
  }
  const entryByDescriptor = new Map<string, LockedInstance>();
  const instancesByLocator = new Map<string, LockedInstance>();
  for (const [groupedDescriptor, raw] of Object.entries(lock)) {
    if (groupedDescriptor === '__metadata') continue;
    const entry = record(raw);
    const descriptors = splitYarnSelectors(groupedDescriptor);
    if (
      !entry ||
      typeof entry.version !== 'string' ||
      !semver.valid(entry.version)
    ) {
      warnings.push(
        `Yarn descriptor has no exact version: ${groupedDescriptor.slice(0, 200)}`
      );
      continue;
    }
    if (descriptors.length === 0) {
      warnings.push(
        `Yarn descriptor is unsupported: ${groupedDescriptor.slice(0, 200)}`
      );
      continue;
    }
    const descriptorInfos = descriptors.map((descriptor) => ({
      descriptor,
      info: yarnDescriptorName(descriptor)
    }));
    const validDescriptors = descriptorInfos.filter(
      (
        item
      ): item is {
        descriptor: string;
        info: NonNullable<ReturnType<typeof yarnDescriptorName>>;
      } => item.info !== undefined
    );
    if (validDescriptors.length !== descriptors.length) {
      warnings.push(
        `Yarn descriptor is unsupported: ${groupedDescriptor.slice(0, 200)}`
      );
      continue;
    }
    const fallbackName = validDescriptors[0]?.info.name;
    if (!fallbackName) continue;
    const resolution =
      typeof entry.resolution === 'string'
        ? entry.resolution
        : `${fallbackName}@${entry.version}`;
    const name = yarnDescriptorName(resolution)?.name ?? fallbackName;
    // Berry's `resolution` commonly points every peer-qualified virtual
    // locator at the same downloaded archive. That archive identity is not an
    // installed-instance identity: the virtual descriptor's hash records the
    // peer environment and controls which dependency bindings are visible.
    // Preserve that context while still collapsing grouped range selectors
    // that Yarn emitted for the same virtual locator.
    const virtualContexts = [
      ...new Set(
        validDescriptors
          .map(({ info }) => info.selector)
          .filter((selector) => selector.startsWith('virtual:'))
          .map(
            (selector) =>
              selector.slice('virtual:'.length).split('#', 1)[0] ?? ''
          )
      )
    ].sort();
    const resolutionReference =
      yarnDescriptorName(resolution)?.selector ??
      (classic ? `npm:${entry.version}` : undefined);
    if (virtualContexts.length > 1 || !resolutionReference) {
      warnings.push(
        `Yarn package has an ambiguous PnP resolution context: ${groupedDescriptor.slice(0, 200)}`
      );
    }
    const resolutionContext = resolutionReference
      ? virtualContexts.length === 1
        ? `virtual:${virtualContexts[0]}#${resolutionReference}`
        : resolutionReference
      : undefined;
    const identityKey = `${name}\0${entry.version}\0${String(entry.integrity ?? '')}\0${resolution}\0${safeResolved(entry.resolved) ?? ''}\0${virtualContexts.join(',')}`;
    let item = instancesByLocator.get(identityKey);
    if (!item) {
      const virtualName = createHash('sha256')
        .update(identityKey)
        .digest('hex')
        .slice(0, 20);
      item = {
        locator: `${resolution}#${createHash('sha256').update(identityKey).digest('hex').slice(0, 16)}`,
        name,
        version: entry.version,
        installPath: `yarn:pnp/${virtualName}`,
        integrity:
          typeof entry.integrity === 'string'
            ? entry.integrity.slice(0, 1_024)
            : undefined,
        resolved: safeResolved(entry.resolved),
        dev: entry.dev === true,
        optional: entry.optional === true,
        resolutionContext,
        dependencies: record(entry.dependencies),
        optionalDependencies: record(entry.optionalDependencies)
      };
      instancesByLocator.set(identityKey, item);
    }
    for (const { descriptor } of validDescriptors) {
      const existing = entryByDescriptor.get(descriptor);
      if (existing && existing !== item) {
        warnings.push(
          `Yarn descriptor resolves to multiple locked instances: ${descriptor.slice(0, 200)}`
        );
        continue;
      }
      entryByDescriptor.set(descriptor, item);
    }
  }
  const instances = [...instancesByLocator.values()];
  const entryCandidatesByName = new Map<
    string,
    Array<{ descriptor: string; item: LockedInstance }>
  >();
  for (const [descriptor, item] of entryByDescriptor) {
    const name = yarnDescriptorName(descriptor)?.name;
    if (!name) continue;
    const candidates = entryCandidatesByName.get(name) ?? [];
    candidates.push({ descriptor, item });
    entryCandidatesByName.set(name, candidates);
  }
  let yarnResolverCandidateWork = 0;
  let yarnResolverCandidateWorkExceeded = false;
  const resolve = (
    name: string,
    requirement: string
  ): LockedInstance | undefined => {
    if (requirement.startsWith('workspace:')) return workspacesByName.get(name);
    const yarnRequirement = requirement.startsWith('npm:')
      ? requirement
      : `npm:${requirement}`;
    const descriptors = [
      `${name}@${requirement}`,
      `${name}@${yarnRequirement}`
    ];
    for (const descriptor of descriptors) {
      const exact = entryByDescriptor.get(descriptor);
      if (exact) return exact;
    }
    if (yarnResolverCandidateWorkExceeded) return undefined;
    const matches: LockedInstance[] = [];
    for (const candidate of entryCandidatesByName.get(name) ?? []) {
      if (yarnResolverCandidateWork >= maximumYarnResolverCandidateWork) {
        yarnResolverCandidateWorkExceeded = true;
        warnings.push('Yarn resolver candidate work budget exceeded');
        return undefined;
      }
      yarnResolverCandidateWork += 1;
      if (candidate.descriptor.endsWith(requirement))
        matches.push(candidate.item);
    }
    return matches.length === 1 ? matches[0] : undefined;
  };
  const edgeSpecs = [] as Parameters<typeof makeGraph>[2];
  edgeSpecs.push(...parseSections(manifest, resolve, 'root', true));
  for (const workspace of workspaces) {
    edgeSpecs.push(
      ...parseSections(
        workspace.dependencies ?? {},
        resolve,
        `yarn:${workspace.locator}`,
        true
      )
    );
  }
  // Berry stores grouped selectors under the combined header, not under each
  // individual descriptor. Traverse the parsed unique instance records so a
  // grouped package never loses its transitive edges.
  for (const item of instances) {
    edgeSpecs.push(
      ...parseSections(item, resolve, `yarn:${item.locator}`, false)
    );
  }
  return makeGraph('yarn', [...instances, ...workspaces], edgeSpecs, warnings);
}

export async function readBoundedDependencyText(
  filePath: string,
  maximumBytes = 64 * 1024 * 1024
): Promise<string> {
  const metadata = await lstat(filePath, { bigint: true });
  if (!metadata.isFile() || metadata.size > BigInt(maximumBytes))
    throw new Error(
      'dependency lockfile exceeds the bounded regular-file limit'
    );
  const noFollow =
    process.platform === 'win32' ? 0 : (constants.O_NOFOLLOW ?? 0);
  const handle = await open(filePath, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== metadata.dev ||
      opened.ino !== metadata.ino ||
      opened.size !== metadata.size ||
      opened.mtimeNs !== metadata.mtimeNs
    ) {
      throw new Error('dependency lockfile changed while opening');
    }
    const bytes = await handle.readFile();
    if (bytes.length > maximumBytes)
      throw new Error('dependency lockfile exceeds the bounded read limit');
    const current = await lstat(filePath, { bigint: true });
    if (
      !current.isFile() ||
      current.dev !== opened.dev ||
      current.ino !== opened.ino ||
      current.size !== opened.size ||
      current.mtimeNs !== opened.mtimeNs
    ) {
      throw new Error('dependency lockfile changed while reading');
    }
    return bytes.toString('utf8');
  } finally {
    await handle.close();
  }
}

const readBoundedText = readBoundedDependencyText;

function readCapturedText(
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
    throw new Error(`Dependency snapshot has no text for ${relativePath}.`);
  }
  if (Buffer.byteLength(text, 'utf8') > 64 * 1024 * 1024) {
    throw new Error('dependency lockfile exceeds the bounded snapshot limit');
  }
  return text;
}
