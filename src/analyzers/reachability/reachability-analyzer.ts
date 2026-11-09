import type {
  Analyzer,
  AnalyzerContext,
  AnalyzerResult
} from '../../contracts/analyzer.js';
import { realpathSync, type Dirent } from 'node:fs';
import { lstat, readdir, realpath as realpathAsync } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import ts from 'typescript';
import type { Finding } from '../../contracts/finding.js';
import { coverageOf } from '../../contracts/analysis.js';
import { createScannerContext } from '../../core/scanner-context.js';
import { sourceProvenanceFor } from '../../core/source-provenance.js';
import { TextFileReader } from '../../core/text-file-reader.js';
import {
  readNpmDependencyGraph,
  type DependencyFileSource
} from '../../core/dependencies/inventory.js';
import { extractPackageImports, type ImportReference } from './import-graph.js';
import type { ScannerContext } from '../../core/scanner-context.js';
import {
  dependencyFileSourceFromSnapshot,
  snapshotContentProvider,
  type ProjectSnapshot
} from '../../application/project-snapshot.js';

const codeExtensions = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);
const maxInstalledPackageManifests = 20_000;
const maxInstalledPackageManifestBytes = 64 * 1024;
const maxInstalledPackageManifestTotalBytes = 64 * 1024 * 1024;
const maxYarnNodeModulesEntries = 100_000;

type InstalledPackageManifest = {
  name: string;
  version: string;
  directory: string;
};

type YarnPnpDependency = { name: string; reference: string };
type YarnPnpPackage = {
  name: string;
  reference: string;
  location: string;
  dependencies: Map<string, YarnPnpDependency>;
};
type YarnPnpState = Map<string, YarnPnpPackage>;

const unsupportedStaticValue = Symbol('unsupported static PnP value');

/** Extracts only inert literals from Yarn's generated runtime-state object. */
function staticPnpValue(
  node: ts.Expression
): unknown | typeof unsupportedStaticValue {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
    return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (node.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isArrayLiteralExpression(node)) {
    const values: unknown[] = [];
    for (const element of node.elements) {
      if (!ts.isExpression(element)) return unsupportedStaticValue;
      const value = staticPnpValue(element);
      if (value === unsupportedStaticValue) return value;
      values.push(value);
    }
    return values;
  }
  if (ts.isObjectLiteralExpression(node)) {
    const value: Record<string, unknown> = Object.create(null) as Record<
      string,
      unknown
    >;
    for (const property of node.properties) {
      if (!ts.isPropertyAssignment(property)) return unsupportedStaticValue;
      const key = property.name;
      const name =
        ts.isIdentifier(key) ||
        ts.isStringLiteral(key) ||
        ts.isNumericLiteral(key)
          ? key.text
          : undefined;
      if (name === undefined || Object.hasOwn(value, name))
        return unsupportedStaticValue;
      const field = staticPnpValue(property.initializer);
      if (field === unsupportedStaticValue) return field;
      value[name] = field;
    }
    return value;
  }
  const jsonArgument = ts.isCallExpression(node)
    ? node.arguments[0]
    : undefined;
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.expression.getText() === 'JSON' &&
    node.expression.name.text === 'parse' &&
    node.arguments.length === 1 &&
    jsonArgument !== undefined &&
    ts.isStringLiteral(jsonArgument)
  ) {
    try {
      return JSON.parse(jsonArgument.text) as unknown;
    } catch {
      return unsupportedStaticValue;
    }
  }
  return unsupportedStaticValue;
}

function parseYarnPnpState(source: string): YarnPnpState {
  let raw: unknown;
  try {
    raw = JSON.parse(source) as unknown;
  } catch {
    const file = ts.createSourceFile(
      '.pnp.cjs',
      source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.JS
    );
    if (
      ((file as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
        .parseDiagnostics?.length ?? 0) > 0
    )
      throw new Error('Yarn PnP runtime data is malformed');
    let initializer: ts.Expression | undefined;
    const findState = (node: ts.Node): void => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.name.text === 'RAW_RUNTIME_STATE'
      )
        initializer = node.initializer;
      if (!initializer) ts.forEachChild(node, findState);
    };
    findState(file);
    if (!initializer) throw new Error('Yarn PnP runtime state was not found');
    raw = staticPnpValue(initializer);
    if (raw === unsupportedStaticValue)
      throw new Error('Yarn PnP runtime state contains executable values');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error('Yarn PnP runtime state has an invalid shape');
  const registry = (raw as { packageRegistryData?: unknown })
    .packageRegistryData;
  if (!Array.isArray(registry))
    throw new Error('Yarn PnP package registry is unavailable');
  const packages: YarnPnpState = new Map();
  for (const packageRecord of registry) {
    if (
      !Array.isArray(packageRecord) ||
      packageRecord.length !== 2 ||
      typeof packageRecord[0] !== 'string' ||
      !Array.isArray(packageRecord[1])
    )
      throw new Error('Yarn PnP package registry is malformed');
    const name = packageRecord[0];
    for (const locator of packageRecord[1]) {
      if (
        !Array.isArray(locator) ||
        locator.length !== 2 ||
        typeof locator[0] !== 'string' ||
        !locator[1] ||
        typeof locator[1] !== 'object' ||
        Array.isArray(locator[1])
      )
        throw new Error('Yarn PnP package locator is malformed');
      const reference = locator[0];
      const details = locator[1] as {
        packageLocation?: unknown;
        packageDependencies?: unknown;
      };
      if (
        typeof details.packageLocation !== 'string' ||
        details.packageLocation.length > 4_096 ||
        !Array.isArray(details.packageDependencies)
      )
        throw new Error('Yarn PnP package locator has invalid metadata');
      const dependencies = new Map<string, YarnPnpDependency>();
      for (const dependency of details.packageDependencies) {
        if (
          !Array.isArray(dependency) ||
          dependency.length !== 2 ||
          typeof dependency[0] !== 'string'
        )
          throw new Error('Yarn PnP dependency binding is malformed');
        const [dependencyName, rawBinding] = dependency;
        if (rawBinding === null || rawBinding === undefined) continue;
        const binding =
          typeof rawBinding === 'string'
            ? { name: dependencyName, reference: rawBinding }
            : Array.isArray(rawBinding) &&
                rawBinding.length === 2 &&
                rawBinding.every((part) => typeof part === 'string')
              ? {
                  name: rawBinding[0] as string,
                  reference: rawBinding[1] as string
                }
              : rawBinding && typeof rawBinding === 'object'
                ? (rawBinding as { name?: unknown; reference?: unknown })
                : undefined;
        if (
          !binding ||
          typeof binding.name !== 'string' ||
          typeof binding.reference !== 'string' ||
          dependencies.has(dependencyName)
        )
          throw new Error('Yarn PnP dependency binding is invalid');
        dependencies.set(dependencyName, {
          name: binding.name,
          reference: binding.reference
        });
      }
      const key = `${name}\0${reference}`;
      if (packages.has(key))
        throw new Error(
          'Yarn PnP runtime state has duplicate package locators'
        );
      packages.set(key, {
        name,
        reference,
        location: details.packageLocation,
        dependencies
      });
    }
  }
  return packages;
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

type YarnPnpLocation =
  | { kind: 'directory'; absolutePath: string }
  | { kind: 'archive'; absolutePath: string }
  | undefined;

/** Resolves PnP locations without following an escaping symlink or assuming
 * that an in-root path exists. Zip-backed packages stay explicitly unknown
 * until their archive contents have been verified. */
async function resolveYarnPnpLocation(
  root: string,
  location: string
): Promise<YarnPnpLocation> {
  if (
    path.isAbsolute(location) ||
    location.split(/[\\/]+/u).includes('..') ||
    location.includes('\0')
  )
    return undefined;
  const absolutePath = path.resolve(root, location);
  if (!isWithin(root, absolutePath)) return undefined;
  const relative = path.relative(root, absolutePath);
  const archiveMatch = relative.match(/(?:^|[\\/])[^\\/]+\.zip(?=[\\/]|$)/iu);
  if (archiveMatch) {
    const archiveIndex = archiveMatch.index;
    if (archiveIndex === undefined) return undefined;
    const archiveRelative = relative.slice(
      0,
      archiveIndex + archiveMatch[0].length
    );
    const archivePath = path.resolve(root, archiveRelative);
    if (!isWithin(root, archivePath)) return undefined;
    try {
      const archiveStat = await lstat(archivePath, { bigint: true });
      const archiveRealpath = await realpathAsync(archivePath);
      if (
        !archiveStat.isFile() ||
        archiveStat.isSymbolicLink() ||
        !isWithin(root, archiveRealpath) ||
        archiveStat.size > BigInt(128 * 1024 * 1024)
      )
        return undefined;
      return { kind: 'archive', absolutePath: archivePath };
    } catch {
      return undefined;
    }
  }
  try {
    const canonicalPath = await realpathAsync(absolutePath);
    if (!isWithin(root, canonicalPath)) return undefined;
    const directoryStat = await lstat(canonicalPath);
    if (!directoryStat.isDirectory()) return undefined;
    return { kind: 'directory', absolutePath: canonicalPath };
  } catch {
    return undefined;
  }
}

/** Restricts TypeScript's module resolver to paths physically inside the root. */
function createRootBoundResolverHost(root: string): ts.ModuleResolutionHost {
  const canonicalRoot = realpathSync(root);
  const canonicalWithin = (candidate: string): string | undefined => {
    try {
      const canonical = realpathSync(candidate);
      return isWithin(canonicalRoot, canonical) ? canonical : undefined;
    } catch {
      return undefined;
    }
  };
  return {
    fileExists: (fileName) =>
      canonicalWithin(fileName) !== undefined && ts.sys.fileExists(fileName),
    readFile: (fileName) =>
      canonicalWithin(fileName) !== undefined
        ? ts.sys.readFile(fileName)
        : undefined,
    directoryExists: (directoryName) =>
      canonicalWithin(directoryName) !== undefined &&
      (ts.sys.directoryExists?.(directoryName) ?? false),
    getDirectories: (directoryName) =>
      canonicalWithin(directoryName) === undefined
        ? []
        : (ts.sys.getDirectories?.(directoryName) ?? []).filter((directory) =>
            canonicalWithin(path.join(directoryName, directory))
          ),
    realpath: (fileName) => canonicalWithin(fileName) ?? fileName,
    getCurrentDirectory: () => canonicalRoot,
    useCaseSensitiveFileNames: ts.sys.useCaseSensitiveFileNames
  };
}

async function discoverYarnNodeModules(
  root: string,
  expectedNames: ReadonlySet<string>,
  reader: TextFileReader,
  signal?: AbortSignal
): Promise<{
  packages: InstalledPackageManifest[];
  unresolvedNames: Set<string>;
  warnings: string[];
}> {
  const packages: InstalledPackageManifest[] = [];
  const unresolvedNames = new Set<string>();
  const warnings = new Set<string>();
  const pending = [path.join(root, 'node_modules')];
  const visited = new Set<string>();
  let entriesRead = 0;
  while (pending.length > 0) {
    if (signal?.aborted) {
      warnings.add('yarn-node-modules-discovery-cancelled');
      for (const name of expectedNames) unresolvedNames.add(name);
      break;
    }
    const directory = pending.pop();
    if (!directory || visited.has(directory)) continue;
    visited.add(directory);
    if (visited.size > maxYarnNodeModulesEntries) {
      warnings.add('yarn-node-modules-entry-budget-exceeded');
      for (const name of expectedNames) unresolvedNames.add(name);
      break;
    }
    let entries: Dirent[];
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (
        error &&
        typeof error === 'object' &&
        'code' in error &&
        error.code === 'ENOENT'
      )
        continue;
      warnings.add('yarn-node-modules-directory-unavailable');
      for (const name of expectedNames) unresolvedNames.add(name);
      continue;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    const scope = path.basename(directory);
    for (const entry of entries) {
      if (++entriesRead > maxYarnNodeModulesEntries) {
        warnings.add('yarn-node-modules-entry-budget-exceeded');
        for (const name of expectedNames) unresolvedNames.add(name);
        pending.length = 0;
        break;
      }
      if (entry.name === '.bin' || entry.name === '.cache') continue;
      const packageName = scope.startsWith('@')
        ? `${scope}/${entry.name}`
        : entry.name;
      const candidate = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        if (expectedNames.has(packageName)) {
          unresolvedNames.add(packageName);
          warnings.add(
            `yarn-installed-package-symlink-unresolved:${packageName}`
          );
        }
        continue;
      }
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('@')) {
        pending.push(candidate);
        continue;
      }
      if (expectedNames.has(packageName)) {
        const manifest = await reader.read(
          path.join(candidate, 'package.json'),
          signal
        );
        if (manifest.status === 'ok') {
          try {
            const value: unknown = JSON.parse(manifest.content);
            if (
              value &&
              typeof value === 'object' &&
              'name' in value &&
              value.name === packageName &&
              'version' in value &&
              typeof value.version === 'string'
            ) {
              packages.push({
                name: packageName,
                version: value.version,
                directory: candidate
              });
            } else {
              unresolvedNames.add(packageName);
              warnings.add(
                `yarn-installed-package-identity-invalid:${packageName}`
              );
            }
          } catch {
            unresolvedNames.add(packageName);
            warnings.add(
              `yarn-installed-package-manifest-invalid:${packageName}`
            );
          }
        } else {
          unresolvedNames.add(packageName);
          warnings.add(
            `yarn-installed-package-manifest-unavailable:${packageName}`
          );
        }
      }
      pending.push(path.join(candidate, 'node_modules'));
    }
  }
  return {
    packages,
    unresolvedNames,
    warnings: [...warnings].sort()
  };
}

export type PackageReachability = {
  packageId: string;
  packageName: string;
  packageVersion: string;
  installPath: string;
  state: 'reachable' | 'possibly-reachable' | 'not-observed' | 'unknown';
  direct: boolean;
  development: boolean;
  references: Array<
    ImportReference & {
      file: string;
    }
  >;
};

export class ReachabilityAnalyzer implements Analyzer {
  readonly id = 'package-reachability';
  readonly version = '1.0.0';

  /** Maps observed project imports to the resolved dependency inventory. */
  async analyze(context: AnalyzerContext): Promise<AnalyzerResult> {
    const startedAt = performance.now();
    const snapshot = context.options?.snapshot as ProjectSnapshot | undefined;
    const fileSource =
      (context.options?.dependencyFileSource as
        DependencyFileSource | undefined) ??
      (snapshot ? dependencyFileSourceFromSnapshot(snapshot) : undefined);
    const dependencyGraph = await readNpmDependencyGraph(
      context.root,
      fileSource
    );
    const dependencies = dependencyGraph.packages;
    const sharedContext = context.options?.scannerContext as
      ScannerContext | undefined;
    const scannerContext =
      sharedContext ?? (await createScannerContext(context.root));
    const contentProvider = snapshot
      ? snapshotContentProvider(snapshot)
      : undefined;
    const reader = new TextFileReader(undefined, { root: scannerContext.root });
    const warnings: string[] = [];
    const warningSet = new Set<string>();
    const addWarning = (warning: string): void => {
      if (warningSet.has(warning) || warnings.length >= 100) return;
      warningSet.add(warning);
      warnings.push(warning);
    };
    for (const warning of dependencyGraph.warnings) addWarning(warning);
    let eligible = 0;
    let scanned = 0;
    let skipped = 0;
    let cancelled = false;
    let referenceCount = 0;
    let referenceTruncated = false;
    let dynamicImportsSeen = false;
    let importCount = 0;
    const maxImports = 100_000;
    const maxReferences = 10_000;
    const maxReferencesPerPackage = 500;

    const references = new Map<string, PackageReachability['references']>();
    const referenceKeys = new Map<string, Set<string>>();
    const unresolved = new Set<string>();
    const dependenciesByName = new Map<string, typeof dependencies>();
    const yarnWorkspaceIds = new Map<string, string>();
    const yarnEdgesByOwnerAndName = new Map<string, Set<string>>();
    const resolverHost = createRootBoundResolverHost(scannerContext.root);
    const metadataReader = new TextFileReader(
      {
        maxFiles: maxInstalledPackageManifests,
        maxFileBytes: maxInstalledPackageManifestBytes,
        maxTotalBytes: maxInstalledPackageManifestTotalBytes
      },
      { root: scannerContext.root }
    );
    for (const dependency of dependencies) {
      const sameName = dependenciesByName.get(dependency.name) ?? [];
      sameName.push(dependency);
      dependenciesByName.set(dependency.name, sameName);
      if (dependency.manager === 'yarn' && dependency.workspace)
        yarnWorkspaceIds.set(dependency.workspace, dependency.id);
    }
    if (!dependencyGraph.complete)
      for (const dependency of dependencies) unresolved.add(dependency.id);
    const instancePaths = new Map<string, string>();
    const yarnDependencies = dependencies.filter(
      (dependency) =>
        dependency.manager === 'yarn' &&
        dependency.installPath.startsWith('yarn:pnp/')
    );
    const yarnGraphPackages = dependencies.filter(
      (dependency) => dependency.manager === 'yarn'
    );
    const yarnPnpMode =
      yarnDependencies.length > 0 &&
      scannerContext.files.some((file) =>
        ['.pnp.cjs', '.pnp.data.json', '.pnp.loader.mjs'].includes(
          file.relativePath
        )
      );
    if (!yarnPnpMode) {
      for (const edge of dependencyGraph.edges) {
        const key = `${edge.from}\0${edge.name}`;
        const targets = yarnEdgesByOwnerAndName.get(key) ?? new Set<string>();
        targets.add(edge.to);
        yarnEdgesByOwnerAndName.set(key, targets);
      }
    }
    const yarnDependencyIds = new Set(
      yarnDependencies.map((dependency) => dependency.id)
    );
    const installedPathById = new Map<string, string>();
    if (yarnPnpMode) {
      const pnpFile =
        scannerContext.files.find(
          (file) => file.relativePath === '.pnp.data.json'
        ) ??
        scannerContext.files.find((file) => file.relativePath === '.pnp.cjs');
      let pnpState: YarnPnpState | undefined;
      if (!pnpFile) {
        addWarning('yarn-pnp-runtime-state-unavailable');
      } else {
        const read = contentProvider
          ? await contentProvider(pnpFile)
          : await reader.read(
              pnpFile.absolutePath,
              context.signal,
              pnpFile.snapshot
            );
        if (read.status !== 'ok') {
          addWarning(`yarn-pnp-runtime-state-${read.status}`);
        } else {
          try {
            pnpState = parseYarnPnpState(read.content);
          } catch {
            addWarning('yarn-pnp-runtime-state-invalid');
          }
        }
      }
      const pnpById = new Map<string, YarnPnpPackage>();
      const identityById = new Map(dependencies.map((item) => [item.id, item]));
      if (pnpState) {
        for (const dependency of yarnGraphPackages) {
          const runtimePackage = dependency.resolutionContext
            ? pnpState.get(
                `${dependency.name}\0${dependency.resolutionContext}`
              )
            : undefined;
          const validatedLocation = runtimePackage
            ? await resolveYarnPnpLocation(
                scannerContext.root,
                runtimePackage.location
              )
            : undefined;
          if (!runtimePackage || !validatedLocation) {
            unresolved.add(dependency.id);
            addWarning(`yarn-pnp-package-identity-unresolved:${dependency.id}`);
            continue;
          }
          if (validatedLocation.kind === 'directory') {
            const installedManifest = await metadataReader.read(
              path.join(validatedLocation.absolutePath, 'package.json'),
              context.signal
            );
            let installedIdentity: unknown;
            try {
              if (installedManifest.status === 'ok')
                installedIdentity = JSON.parse(installedManifest.content);
            } catch {
              installedIdentity = undefined;
            }
            if (
              !installedIdentity ||
              typeof installedIdentity !== 'object' ||
              !('name' in installedIdentity) ||
              installedIdentity.name !== dependency.name ||
              !('version' in installedIdentity) ||
              installedIdentity.version !== dependency.version
            ) {
              unresolved.add(dependency.id);
              addWarning(
                `yarn-pnp-installed-identity-unverified:${dependency.id}`
              );
              continue;
            }
          }
          pnpById.set(dependency.id, runtimePackage);
          if (validatedLocation.kind === 'archive') {
            unresolved.add(dependency.id);
            addWarning(`yarn-pnp-archive-content-unverified:${dependency.id}`);
          } else {
            installedPathById.set(
              dependency.id,
              path
                .relative(scannerContext.root, validatedLocation.absolutePath)
                .split(path.sep)
                .join('/')
            );
          }
        }
        const rootPackages = [...pnpState.values()].filter(
          (item) =>
            item.reference === 'workspace:.' &&
            path.resolve(scannerContext.root, item.location) ===
              scannerContext.root
        );
        const rootPackage =
          rootPackages.length === 1 ? rootPackages[0] : undefined;
        if (!rootPackage) addWarning('yarn-pnp-root-identity-unresolved');
        for (const edge of dependencyGraph.edges) {
          const owner =
            edge.from === 'root' ? rootPackage : pnpById.get(edge.from);
          const target = pnpById.get(edge.to);
          const identity = identityById.get(edge.to);
          const binding = owner?.dependencies.get(edge.name);
          const bindingMatches =
            binding !== undefined &&
            target !== undefined &&
            identity !== undefined &&
            binding.name === target.name &&
            binding.reference === identity.resolutionContext;
          if (!bindingMatches) {
            unresolved.add(edge.to);
            addWarning(`yarn-pnp-dependency-binding-unverified:${edge.to}`);
            continue;
          }
          const key = `${edge.from}\0${edge.name}`;
          const targets = yarnEdgesByOwnerAndName.get(key) ?? new Set<string>();
          targets.add(edge.to);
          yarnEdgesByOwnerAndName.set(key, targets);
        }
      } else {
        for (const dependency of yarnGraphPackages)
          unresolved.add(dependency.id);
      }
    }
    const yarnInstalled =
      yarnDependencies.length && !yarnPnpMode
        ? await discoverYarnNodeModules(
            scannerContext.root,
            new Set(yarnDependencies.map((dependency) => dependency.name)),
            metadataReader,
            context.signal
          )
        : { packages: [], unresolvedNames: new Set<string>(), warnings: [] };
    for (const warning of yarnInstalled.warnings) addWarning(warning);
    const yarnInstancesByVersion = new Map<string, typeof yarnDependencies>();
    const yarnPathsByVersion = new Map<string, InstalledPackageManifest[]>();
    if (!yarnPnpMode) {
      for (const dependency of yarnDependencies) {
        const key = `${dependency.name}\0${dependency.version}`;
        const instances = yarnInstancesByVersion.get(key) ?? [];
        instances.push(dependency);
        yarnInstancesByVersion.set(key, instances);
      }
      for (const installed of yarnInstalled.packages) {
        const key = `${installed.name}\0${installed.version}`;
        const locations = yarnPathsByVersion.get(key) ?? [];
        locations.push(installed);
        yarnPathsByVersion.set(key, locations);
      }
      for (const dependency of yarnDependencies) {
        const key = `${dependency.name}\0${dependency.version}`;
        const identities = yarnInstancesByVersion.get(key) ?? [];
        const locations = yarnPathsByVersion.get(key) ?? [];
        if (
          identities.length !== 1 ||
          locations.length === 0 ||
          yarnInstalled.unresolvedNames.has(dependency.name)
        ) {
          unresolved.add(dependency.id);
          addWarning(`yarn-installed-instance-unresolved:${dependency.id}`);
          continue;
        }
        for (const location of locations) {
          const resolvedPath = await realpathAsync(location.directory).catch(
            () => undefined
          );
          if (!resolvedPath || !isWithin(scannerContext.root, resolvedPath)) {
            unresolved.add(dependency.id);
            addWarning(`yarn-installed-location-outside-root:${dependency.id}`);
            continue;
          }
          instancePaths.set(resolvedPath, dependency.id);
          if (!installedPathById.has(dependency.id)) {
            installedPathById.set(
              dependency.id,
              path
                .relative(scannerContext.root, resolvedPath)
                .split(path.sep)
                .join('/')
            );
          }
        }
      }
    }
    for (const dependency of dependencies) {
      if (context.signal?.aborted) {
        unresolved.add(dependency.id);
        addWarning('installed-package-identity-check-cancelled');
        continue;
      }
      if (yarnDependencyIds.has(dependency.id)) continue;
      const installPath = path.resolve(
        scannerContext.root,
        dependency.installPath
      );
      const relativeInstallPath = path.relative(
        scannerContext.root,
        installPath
      );
      const resolvedPath = await realpathAsync(installPath).catch(
        () => undefined
      );
      if (
        !resolvedPath ||
        path.isAbsolute(relativeInstallPath) ||
        relativeInstallPath === '..' ||
        relativeInstallPath.startsWith(`..${path.sep}`) ||
        !isWithin(scannerContext.root, resolvedPath)
      ) {
        unresolved.add(dependency.id);
        addWarning(`dependency-install-location-unavailable:${dependency.id}`);
        continue;
      }
      const manifest = await metadataReader.read(
        path.join(installPath, 'package.json'),
        context.signal
      );
      if (manifest.status !== 'ok') {
        unresolved.add(dependency.id);
        addWarning(
          `dependency-installed-manifest-unavailable:${dependency.id}`
        );
        continue;
      }
      let installed: unknown;
      try {
        installed = JSON.parse(manifest.content);
      } catch {
        unresolved.add(dependency.id);
        addWarning(`dependency-installed-manifest-invalid:${dependency.id}`);
        continue;
      }
      if (
        !installed ||
        typeof installed !== 'object' ||
        !('name' in installed) ||
        installed.name !== dependency.name ||
        !('version' in installed) ||
        installed.version !== dependency.version
      ) {
        unresolved.add(dependency.id);
        addWarning(`dependency-installed-identity-mismatch:${dependency.id}`);
        continue;
      }
      instancePaths.set(resolvedPath, dependency.id);
    }
    const sourceProvenance = new Map<
      string,
      ReturnType<typeof sourceProvenanceFor>
    >();

    const codeFiles = scannerContext.files.filter(
      (file) =>
        codeExtensions.has(file.extension) &&
        !file.relativePath.endsWith('.d.ts') &&
        !file.relativePath.startsWith('dist/')
    );
    eligible = codeFiles.length;

    for (const [fileIndex, file] of codeFiles.entries()) {
      if (context.signal?.aborted || cancelled) {
        cancelled = true;
        skipped += codeFiles.length - fileIndex;
        addWarning(`${file.relativePath}: skipped (cancelled)`);
        break;
      }
      const read = contentProvider
        ? await contentProvider(file)
        : await reader.read(file.absolutePath, context.signal, file.snapshot);

      if (read.status !== 'ok') {
        skipped += 1;
        addWarning(`${file.relativePath}: skipped (${read.status})`);
        if (read.status === 'cancelled') {
          cancelled = true;
          skipped += codeFiles.length - fileIndex - 1;
          break;
        }
        continue;
      }
      scanned += 1;
      sourceProvenance.set(file.relativePath, sourceProvenanceFor(file, read));

      const fileReferences = extractPackageImports(
        file.relativePath,
        read.content
      );
      if (importCount + fileReferences.length > maxImports) {
        referenceTruncated = true;
        scanned -= 1;
        skipped += codeFiles.length - fileIndex;
        addWarning(
          'package import analysis exceeded its bounded reference limit'
        );
        break;
      }
      importCount += fileReferences.length;

      for (const reference of fileReferences) {
        if (reference.packageName === '*') {
          dynamicImportsSeen = true;
          addWarning(
            `${file.relativePath}: dynamic package loading could not be resolved`
          );
          continue;
        }
        let packageId: string | undefined;
        if (yarnPnpMode) {
          let directory = path.posix.dirname(file.relativePath);
          let owner = 'root';
          while (directory !== '.') {
            const workspace = yarnWorkspaceIds.get(directory);
            if (workspace) {
              owner = workspace;
              break;
            }
            const parent = path.posix.dirname(directory);
            if (parent === directory) break;
            directory = parent;
          }
          const targetIds =
            yarnEdgesByOwnerAndName.get(`${owner}\0${reference.packageName}`) ??
            new Set<string>();
          if (targetIds.size === 1) packageId = targetIds.values().next().value;
          else if (targetIds.size > 1) {
            for (const id of targetIds) unresolved.add(id);
            addWarning(
              `${file.relativePath}: Yarn PnP dependency binding is ambiguous for ${reference.packageName}`
            );
            continue;
          }
        } else {
          const resolved = ts.resolveModuleName(
            reference.specifier,
            file.absolutePath,
            {
              module: ts.ModuleKind.NodeNext,
              moduleResolution: ts.ModuleResolutionKind.NodeNext,
              target: ts.ScriptTarget.Latest,
              allowJs: true,
              resolveJsonModule: true
            },
            resolverHost
          ).resolvedModule?.resolvedFileName;
          const resolvedFile = resolved
            ? await realpathAsync(resolved).catch(() => undefined)
            : undefined;
          if (
            resolved &&
            (!resolvedFile || !isWithin(scannerContext.root, resolvedFile))
          ) {
            addWarning(
              `${file.relativePath}: package resolution escaped the project root`
            );
            for (const dependency of dependenciesByName.get(
              reference.packageName
            ) ?? [])
              unresolved.add(dependency.id);
            continue;
          }
          let cursor = resolvedFile ? path.dirname(resolvedFile) : undefined;
          while (cursor) {
            packageId = instancePaths.get(cursor);
            if (packageId || cursor === scannerContext.root) break;
            const parent = path.dirname(cursor);
            if (parent === cursor) break;
            cursor = parent;
          }
        }

        if (!packageId) {
          let matchedDependency = false;
          for (const dependency of dependenciesByName.get(
            reference.packageName
          ) ?? []) {
            unresolved.add(dependency.id);
            matchedDependency = true;
          }
          if (matchedDependency) {
            addWarning(
              `${file.relativePath}: package resolution is unknown for ${reference.packageName}`
            );
          }
          continue;
        }

        const current = references.get(packageId) ?? [];
        const seen = referenceKeys.get(packageId) ?? new Set<string>();
        const key = `${file.relativePath}\0${reference.line}\0${reference.column}\0${reference.specifier}\0${reference.kind}`;
        if (seen.has(key)) continue;
        if (
          current.length >= maxReferencesPerPackage ||
          referenceCount >= maxReferences
        ) {
          referenceTruncated = true;
          addWarning(
            'package reference evidence exceeded the bounded retention limit'
          );
          continue;
        }
        seen.add(key);
        referenceKeys.set(packageId, seen);
        referenceCount += 1;
        current.push({ ...reference, file: file.relativePath });
        references.set(packageId, current);
      }
    }

    if (dynamicImportsSeen || referenceTruncated) {
      for (const dependency of dependencies) unresolved.add(dependency.id);
    }

    const packageStates = dependencies.map(
      (dependency): PackageReachability => {
        const packageReferences = references.get(dependency.id) ?? [];

        return {
          packageId: dependency.id,
          packageName: dependency.name,
          packageVersion: dependency.version,
          installPath:
            installedPathById.get(dependency.id) ?? dependency.installPath,
          state: unresolved.has(dependency.id)
            ? 'unknown'
            : packageReferences.length > 0
              ? 'reachable'
              : dependency.direct
                ? 'possibly-reachable'
                : 'not-observed',
          direct: dependency.direct,
          development: dependency.development,
          references: packageReferences
        };
      }
    );

    const findings: Finding[] = packageStates
      .filter((item) => item.state === 'reachable')
      .map((item) => ({
        id: `TLP-REACH-${createHash('sha256').update(item.packageId).digest('hex').slice(0, 20)}`,
        ruleId: 'TLP-REACH-001',
        title: `Package usage observed: ${item.packageName}`,
        category: 'reachability',
        severity: 'info',
        confidence: 'high',
        message: `${item.packageName}@${item.packageVersion} at ${item.installPath} resolves from project source files.`,
        source: 'typescript-ast',
        evidence: item.references.slice(0, 20).map((reference) => ({
          summary:
            `${reference.file}:${reference.line}:${reference.column} ` +
            `${reference.kind} import`,
          fingerprint:
            `${item.packageName}:${reference.file}:` +
            `${reference.line}:${reference.column}`
        })),
        metadata: {
          package: item.packageName,
          packageId: item.packageId,
          packageVersion: item.packageVersion,
          installPath: item.installPath,
          state: item.state,
          direct: item.direct,
          development: item.development,
          references: item.references,
          sourceProvenance: [
            ...new Set(item.references.map((reference) => reference.file))
          ]
            .sort((a, b) => a.localeCompare(b))
            .flatMap((file) => {
              const provenance = sourceProvenance.get(file);
              return provenance ? [provenance] : [];
            })
        }
      }));

    return {
      analyzer: this.id,
      durationMs: Math.round(performance.now() - startedAt),
      findings,
      coverage: coverageOf({
        eligible: eligible + dependencies.length,
        scanned: scanned + dependencies.length - unresolved.size,
        skipped: skipped + unresolved.size,
        failed: 0,
        cancelled
      }),
      warnings: warnings.length > 0 ? warnings : undefined,
      metadata: {
        dependencies: packageStates.length,
        bytesAnalyzed: reader.usage.bytesRead,
        installedPackageManifestBytes: metadataReader.usage.bytesRead,
        reachable: packageStates.filter((item) => item.state === 'reachable')
          .length,
        possiblyReachable: packageStates.filter(
          (item) => item.state === 'possibly-reachable'
        ).length,
        notObserved: packageStates.filter(
          (item) => item.state === 'not-observed'
        ).length,
        packages: packageStates
      }
    };
  }
}
