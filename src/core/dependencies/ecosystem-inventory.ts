import { readdir } from 'node:fs/promises';
import type { Dirent } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import semver from 'semver';
import type {
  DependencyEdge,
  DependencyFileSource,
  DependencyIdentity
} from './inventory.js';
import { readBoundedDependencyText } from './lockfile-resolvers.js';
import {
  captureGoMvsGraph,
  parseGoModuleJsonStream,
  type GoCommandRunner
} from './go-module-graph.js';

type LockedPackage = {
  name: string;
  version: string;
  ecosystem: DependencyIdentity['ecosystem'];
  source: string;
  resolutionConfidence?: 'lockfile' | 'declared-pin' | 'workspace' | 'unknown';
  development?: boolean;
  optional?: boolean;
  integrity?: string;
  direct?: boolean;
  installPath?: string;
  classifier?: string;
  packageType?: string;
  module?: string;
  resolutionContext?: string;
  declaredFeatures?: string[];
  dependencies?: Array<{
    name: string;
    requirement: string;
    section: DependencyEdge['section'];
    module?: string;
    marker?: string;
    extras?: string[];
    requestedFeatures?: string[];
    target?: string;
    alias?: string;
  }>;
};

type RecordValue = Record<string, unknown>;
const maximumComposerWorkspaceManifests = 5_000;
const maximumComposerWorkspaceEntries = 50_000;
const maximumComposerPathRepositories = 128;
const maximumCargoWorkspaceManifests = 5_000;
const maximumGoSourceFiles = 20_000;
const maximumGoSourceFileBytes = 1_048_576;
const maximumGoSourceBytes = 32 * 1024 * 1024;
const maximumPythonRequirementFiles = 128;
const maximumPythonRequirementDepth = 16;
const maximumPythonRequirementBytes = 32 * 1024 * 1024;
const maximumPythonWorkspaceManifests = 5_000;
const maximumPythonWorkspaceEntries = 50_000;
const maximumWorkspaceGlobWork = 16_000_000;
const maximumEcosystemResolutionWork = 250_000;

function asRecord(value: unknown): RecordValue | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as RecordValue)
    : undefined;
}

function identity(item: LockedPackage): DependencyIdentity {
  const installPath =
    item.installPath ?? `${item.ecosystem}:${item.name}@${item.version}`;
  return {
    id: `${item.ecosystem}:${item.source}:${installPath}`,
    ecosystem: item.ecosystem,
    name: item.name,
    version: item.version,
    direct: item.direct ?? false,
    development: item.development ?? false,
    ...(item.optional ? { optional: true } : {}),
    source: item.source,
    resolutionConfidence: item.resolutionConfidence ?? 'lockfile',
    installPath,
    ...(item.module ? { workspace: item.module } : {}),
    ...(item.classifier ? { classifier: item.classifier } : {}),
    ...(item.packageType ? { packageType: item.packageType } : {}),
    ...(item.resolutionContext
      ? { resolutionContext: item.resolutionContext }
      : {}),
    ...(item.declaredFeatures?.length
      ? { declaredFeatures: [...item.declaredFeatures].sort() }
      : {}),
    ...(item.integrity ? { integrity: item.integrity } : {})
  };
}

export type OtherEcosystemInventoryResult = {
  packages: DependencyIdentity[];
  edges: DependencyEdge[];
  warnings: string[];
  complete: boolean;
};

export type OtherEcosystemInventoryOptions = {
  /** Explicitly invoke the Go tool against captured metadata to resolve MVS. */
  allowGoToolExecution?: boolean;
  /** Strict offline mode always disables Go subprocesses. */
  offline?: boolean;
  signal?: AbortSignal;
  /** Injectable process boundary for deterministic integration tests. */
  goCommandRunner?: GoCommandRunner;
};

function exact(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    !/[<>=*^~|,\s]/u.test(value)
  );
}

function fromJsonLock(
  value: unknown,
  ecosystem: LockedPackage['ecosystem'],
  source: string
): LockedPackage[] {
  if (!value || typeof value !== 'object') return [];
  const record = value as Record<string, unknown>;
  if (ecosystem === 'PyPI' && ('default' in record || 'develop' in record)) {
    const output: LockedPackage[] = [];
    for (const section of ['default', 'develop']) {
      const entries = record[section];
      if (!entries || typeof entries !== 'object') continue;
      for (const [name, raw] of Object.entries(entries)) {
        const version =
          raw && typeof raw === 'object'
            ? (raw as Record<string, unknown>).version
            : undefined;
        if (typeof version === 'string' && /^==?\d[^,;\s]*$/u.test(version))
          output.push({
            name: canonicalPythonName(name),
            version: version.replace(/^==?/u, ''),
            ecosystem,
            source,
            development: section === 'develop'
          });
      }
    }
    return output;
  }
  if (ecosystem === 'Packagist') {
    const output: LockedPackage[] = [];
    for (const section of ['packages', 'packages-dev']) {
      const entries = record[section];
      if (!Array.isArray(entries)) continue;
      for (const item of entries) {
        if (!item || typeof item !== 'object') continue;
        const pkg = item as Record<string, unknown>;
        if (
          typeof pkg.name === 'string' &&
          typeof pkg.version === 'string' &&
          exact(pkg.version)
        ) {
          const version = pkg.version.replace(/^v/u, '');
          const stableVersion = semver.valid(version) !== null;
          const distribution = asRecord(pkg.dist);
          const packageSource = asRecord(pkg.source);
          const isPathRepository =
            distribution?.type === 'path' || packageSource?.type === 'path';
          const rawPath =
            typeof distribution?.url === 'string'
              ? distribution.url
              : typeof packageSource?.url === 'string'
                ? packageSource.url
                : undefined;
          const normalizedPath = rawPath
            ? path.posix.normalize(
                rawPath.replaceAll('\\', '/').replace(/^\.\//u, '')
              )
            : undefined;
          const safePath = Boolean(
            normalizedPath &&
            !path.posix.isAbsolute(rawPath?.replaceAll('\\', '/') ?? '') &&
            normalizedPath !== '..' &&
            !normalizedPath.startsWith('../') &&
            !normalizedPath.includes('\0')
          );
          output.push({
            name: pkg.name.toLowerCase(),
            version,
            ecosystem,
            source: isPathRepository
              ? safePath
                ? 'composer.lock:path-repository'
                : 'composer.lock:path-unverified'
              : source,
            ...(!isPathRepository && !stableVersion
              ? { resolutionConfidence: 'unknown' as const }
              : {}),
            ...(isPathRepository
              ? {
                  resolutionConfidence: safePath
                    ? ('workspace' as const)
                    : ('unknown' as const),
                  ...(safePath ? { module: normalizedPath } : {})
                }
              : {}),
            development: section === 'packages-dev',
            dependencies: Object.entries(
              pkg.require && typeof pkg.require === 'object'
                ? (pkg.require as Record<string, unknown>)
                : {}
            ).flatMap(([name, requirement]) =>
              typeof requirement === 'string' &&
              name.toLowerCase() !== 'php' &&
              !name.toLowerCase().startsWith('ext-') &&
              !name.toLowerCase().startsWith('lib-')
                ? [
                    {
                      name: name.toLowerCase(),
                      requirement,
                      section:
                        section === 'packages-dev'
                          ? ('devDependency' as const)
                          : ('dependency' as const)
                    }
                  ]
                : []
            )
          });
        }
      }
    }
    return output;
  }
  return [];
}

function fromTomlLock(
  text: string,
  ecosystem: LockedPackage['ecosystem'],
  source: string,
  warnings: string[]
): LockedPackage[] {
  const output: LockedPackage[] = [];
  const stable = (value: unknown): string => {
    if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
    const record = asRecord(value);
    if (record)
      return `{${Object.keys(record)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${stable(record[key])}`)
        .join(',')}}`;
    return JSON.stringify(value) ?? 'null';
  };
  let document: RecordValue;
  try {
    document = parseToml(text, { unsafeKeyBehaviour: 'throw' }) as RecordValue;
  } catch {
    warnings.push(`toml-lock-invalid:${source}`);
    return output;
  }
  if (!Array.isArray(document.package)) {
    warnings.push(`toml-lock-packages-missing:${source}`);
    return output;
  }
  if (
    ecosystem === 'crates.io' &&
    document.version !== 3 &&
    document.version !== 4
  ) {
    warnings.push('cargo-lock-version-unsupported');
    return output;
  }

  const packageSourceForPython = (
    value: unknown
  ): {
    source: string;
    confidence: LockedPackage['resolutionConfidence'];
    module?: string;
  } => {
    if (value === undefined && source === 'poetry.lock')
      return { source: 'poetry.lock:pypi-default', confidence: 'lockfile' };
    const sourceRecord = asRecord(value);
    const localPath =
      typeof sourceRecord?.editable === 'string'
        ? sourceRecord.editable
        : typeof sourceRecord?.directory === 'string'
          ? sourceRecord.directory
          : undefined;
    if (localPath !== undefined) {
      const normalized = path.posix.normalize(localPath.replaceAll('\\', '/'));
      if (
        path.posix.isAbsolute(normalized) ||
        normalized === '..' ||
        normalized.startsWith('../') ||
        normalized.includes('\0')
      )
        return {
          source: `${source}:workspace-unverified`,
          confidence: 'unknown'
        };
      return {
        source: `${source}:workspace`,
        confidence: 'workspace',
        module: normalized === '.' ? 'root' : normalized
      };
    }
    const registry =
      typeof value === 'string'
        ? value
        : typeof sourceRecord?.registry === 'string'
          ? sourceRecord.registry
          : undefined;
    if (registry) {
      try {
        const url = new URL(registry);
        if (
          url.protocol === 'https:' &&
          !url.username &&
          !url.password &&
          !url.search &&
          !url.hash &&
          url.hostname === 'pypi.org' &&
          /^\/(?:simple|pypi)(?:\/|$)/u.test(url.pathname)
        )
          return { source: `${source}:pypi`, confidence: 'lockfile' };
      } catch {
        // Invalid and credential-bearing source URLs are hashed below.
      }
    }
    return {
      source: `${source}:source-unverified:${createHash('sha256').update(stable(value)).digest('hex').slice(0, 16)}`,
      confidence: 'unknown'
    };
  };

  for (const rawPackage of document.package) {
    const pkg = asRecord(rawPackage);
    if (!pkg) {
      warnings.push(`toml-lock-package-unresolved:${source}`);
      continue;
    }
    const packageName = pkg?.name;
    const version = pkg?.version;
    if (
      typeof packageName !== 'string' ||
      typeof version !== 'string' ||
      !exact(version) ||
      version.length > 256
    ) {
      warnings.push(`toml-lock-package-unresolved:${source}`);
      continue;
    }
    const dependencies: NonNullable<LockedPackage['dependencies']> = [];
    const addDependency = (
      rawName: unknown,
      rawValue: unknown,
      section: DependencyEdge['section'] = 'dependency',
      extra?: string
    ): void => {
      if (typeof rawName !== 'string' || !rawName || rawName.length > 256)
        return;
      const dep = asRecord(rawValue);
      const name =
        ecosystem === 'PyPI' ? canonicalPythonName(rawName) : rawName;
      const requirement =
        typeof rawValue === 'string'
          ? rawValue
          : typeof dep?.version === 'string'
            ? dep.version
            : '*';
      const marker =
        typeof dep?.marker === 'string'
          ? dep.marker
          : typeof dep?.markers === 'string'
            ? dep.markers
            : undefined;
      const extras = Array.isArray(dep?.extras)
        ? dep.extras
            .filter((item): item is string => typeof item === 'string')
            .sort()
        : extra
          ? [extra]
          : undefined;
      dependencies.push({
        name,
        requirement,
        section: dep?.optional === true ? 'optionalDependency' : section,
        ...(marker ? { marker } : {}),
        ...(extras?.length ? { extras } : {})
      });
    };
    const rawDependencies = pkg?.dependencies;
    if (Array.isArray(rawDependencies)) {
      for (const rawDependency of rawDependencies) {
        if (typeof rawDependency === 'string' && ecosystem === 'crates.io') {
          const match = rawDependency.match(
            /^(.+?)\s+([^\s]+)(?:\s+\(([^)]+)\))?$/u
          );
          if (match?.[1] && match[2]) addDependency(match[1], match[2]);
          else warnings.push(`toml-lock-dependency-unresolved:${source}`);
        } else {
          const dependency = asRecord(rawDependency);
          if (dependency) addDependency(dependency.name, dependency);
          else warnings.push(`toml-lock-dependency-unresolved:${source}`);
        }
      }
    } else if (asRecord(rawDependencies)) {
      for (const [name, requirement] of Object.entries(
        asRecord(rawDependencies) ?? {}
      ))
        addDependency(name, requirement);
    } else if (rawDependencies !== undefined) {
      warnings.push(`toml-lock-dependencies-invalid:${source}`);
    }

    const optionalDependencies = asRecord(pkg?.['optional-dependencies']);
    for (const [extra, rawItems] of Object.entries(
      optionalDependencies ?? {}
    )) {
      if (Array.isArray(rawItems)) {
        for (const rawItem of rawItems) {
          if (typeof rawItem === 'string')
            addDependency(rawItem, '*', 'optionalDependency', extra);
          else {
            const dependency = asRecord(rawItem);
            if (dependency)
              addDependency(
                dependency.name,
                { ...dependency, extras: [extra] },
                'optionalDependency',
                extra
              );
          }
        }
      } else if (asRecord(rawItems)) {
        for (const [name, requirement] of Object.entries(
          asRecord(rawItems) ?? {}
        ))
          addDependency(name, requirement, 'optionalDependency', extra);
      } else {
        warnings.push(`toml-lock-extra-invalid:${source}`);
      }
    }

    const markerFields =
      ecosystem === 'PyPI'
        ? {
            markers: pkg.markers ?? pkg['resolution-markers'],
            groups: pkg.groups,
            optional: pkg.optional === true ? true : undefined,
            providesExtras: pkg.provides_extras
          }
        : undefined;
    const markerContext = markerFields
      ? Object.fromEntries(
          Object.entries(markerFields).filter(
            ([, value]) => value !== undefined
          )
        )
      : undefined;
    const context =
      markerContext && Object.keys(markerContext).length > 0
        ? stable(markerContext)
        : '';
    if (context.length > 1_024)
      warnings.push(`toml-lock-context-over-budget:${source}`);
    const resolutionContext =
      markerContext !== undefined &&
      context.length > 0 &&
      context.length <= 1_024
        ? context
        : undefined;
    let packageSource = source;
    let resolutionConfidence: LockedPackage['resolutionConfidence'] =
      'lockfile';
    let packageModule: string | undefined;
    let integrity = typeof pkg.checksum === 'string' ? pkg.checksum : undefined;
    if (ecosystem === 'crates.io') {
      const provenance = cargoProvenance(
        typeof pkg.source === 'string' ? pkg.source : undefined,
        integrity
      );
      packageSource = provenance.source;
      resolutionConfidence = provenance.resolutionConfidence;
      integrity = provenance.integrity;
      if (provenance.warning) warnings.push(provenance.warning);
    } else if (ecosystem === 'PyPI') {
      const provenance = packageSourceForPython(pkg.source);
      packageSource = provenance.source;
      resolutionConfidence = provenance.confidence;
      if (provenance.module) packageModule = provenance.module;
      if (resolutionConfidence === 'unknown')
        warnings.push(`python-source-provenance-unverified:${source}`);
    }
    const normalizedName =
      ecosystem === 'PyPI' ? canonicalPythonName(packageName) : packageName;
    const variant = resolutionContext
      ? `:context-${createHash('sha256').update(resolutionContext).digest('hex').slice(0, 16)}`
      : '';
    output.push({
      name: normalizedName,
      version: version.replace(/^v/u, ''),
      ecosystem,
      source: packageSource,
      resolutionConfidence,
      ...(integrity ? { integrity } : {}),
      ...(resolutionContext ? { resolutionContext } : {}),
      ...(packageModule ? { module: packageModule } : {}),
      installPath: `${packageSource}:${packageModule ?? ''}:${normalizedName}@${version}${variant}`,
      dependencies
    });
  }
  return output;
}

function cargoProvenance(
  source: string | undefined,
  checksum: string | undefined
): {
  source: string;
  resolutionConfidence: NonNullable<LockedPackage['resolutionConfidence']>;
  integrity?: string;
  warning?: string;
} {
  if (!source) {
    return {
      source: 'Cargo.lock:path-or-workspace-unverified',
      resolutionConfidence: 'unknown'
    };
  }

  const scheme = source.startsWith('registry+')
    ? 'registry+'
    : source.startsWith('sparse+')
      ? 'sparse+'
      : source.startsWith('git+')
        ? 'git+'
        : undefined;
  if (scheme === 'registry+' || scheme === 'sparse+') {
    try {
      const url = new URL(source.slice(scheme.length));
      const officialRegistry =
        url.protocol === 'https:' &&
        !url.username &&
        !url.password &&
        !url.search &&
        !url.hash &&
        ((url.hostname === 'github.com' &&
          /^\/rust-lang\/crates\.io-index(?:\.git)?\/?$/u.test(url.pathname)) ||
          (url.hostname === 'index.crates.io' && /^\/?$/u.test(url.pathname)));
      if (officialRegistry && /^[a-f0-9]{64}$/iu.test(checksum ?? '')) {
        return {
          source: 'Cargo.lock:registry:crates.io',
          resolutionConfidence: 'lockfile',
          integrity: checksum
        };
      }
    } catch {
      // The redacted unknown result below preserves incomplete coverage.
    }
    return {
      source: `Cargo.lock:registry-unverified:${createHash('sha256').update(source).digest('hex').slice(0, 16)}`,
      resolutionConfidence: 'unknown',
      warning: 'cargo-registry-provenance-unverified'
    };
  }

  if (scheme === 'git+') {
    return {
      source: `Cargo.lock:git-unverified:${createHash('sha256').update(source).digest('hex').slice(0, 16)}`,
      resolutionConfidence: 'unknown',
      warning: 'cargo-git-provenance-unverified'
    };
  }

  return {
    source: `Cargo.lock:source-unverified:${createHash('sha256').update(source).digest('hex').slice(0, 16)}`,
    resolutionConfidence: 'unknown',
    warning: 'cargo-source-provenance-unverified'
  };
}

type CargoDependencyDeclaration = {
  name: string;
  alias: string;
  requirement: string;
  section: DependencyEdge['section'];
  module?: string;
  target?: string;
  requestedFeatures?: string[];
};

function cargoPatternMatches(
  pattern: string,
  directory: string,
  budget: { used: number; exceeded: boolean }
): boolean {
  if (pattern.length > 512 || !pattern) return false;
  budget.used += pattern.length;
  if (budget.used > maximumWorkspaceGlobWork) {
    budget.exceeded = true;
    return false;
  }
  if (
    path.posix.isAbsolute(pattern) ||
    pattern.includes('\\') ||
    pattern.includes('\0') ||
    pattern.split('/').some((part) => part === '..')
  )
    return false;
  return workspacePatternMatches(pattern, directory, budget);
}

function cargoWorkspacePatterns(
  raw: unknown,
  field: 'members' | 'exclude',
  warnings: string[]
): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    warnings.push(`cargo-workspace-${field}-invalid`);
    return [];
  }
  if (raw.length > maximumCargoWorkspaceManifests) {
    warnings.push('cargo-workspace-pattern-budget-exceeded');
    return raw
      .filter((pattern): pattern is string => typeof pattern === 'string')
      .slice(0, maximumCargoWorkspaceManifests);
  }
  const patterns = raw.filter(
    (pattern): pattern is string => typeof pattern === 'string'
  );
  if (
    patterns.length !== raw.length ||
    patterns.some(
      (pattern) =>
        !pattern ||
        pattern.length > 512 ||
        path.posix.isAbsolute(pattern) ||
        pattern.includes('\\') ||
        pattern.includes('\0') ||
        pattern.split('/').some((part) => part === '..')
    )
  )
    warnings.push(`cargo-workspace-${field}-invalid`);
  return patterns.filter(
    (pattern) =>
      pattern.length > 0 &&
      pattern.length <= 512 &&
      !path.posix.isAbsolute(pattern) &&
      !pattern.includes('\\') &&
      !pattern.includes('\0') &&
      !pattern.split('/').some((part) => part === '..')
  );
}

function cargoRequirementMatches(
  version: string,
  requirement: string
): boolean {
  const normalizedVersion = version.replace(/^v/u, '');
  const normalizedRequirement = requirement.trim().replace(/^=/u, '');
  if (normalizedRequirement === '*' || normalizedRequirement.length === 0)
    return true;
  if (semver.valid(normalizedRequirement) && semver.valid(normalizedVersion))
    return semver.eq(normalizedVersion, normalizedRequirement);
  return Boolean(
    semver.valid(normalizedVersion) &&
    semver.validRange(normalizedRequirement) &&
    semver.satisfies(normalizedVersion, normalizedRequirement, {
      includePrerelease: true
    })
  );
}

/** Resolves a PEP 440-style requirement only against captured exact lock entries. */
function pythonRequirementMatches(
  version: string,
  requirement: string
): boolean {
  const normalizeRelease = (value: string): string | undefined => {
    const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/iu.exec(value.trim());
    if (!match?.[1]) return undefined;
    return `${Number(match[1])}.${Number(match[2] ?? 0)}.${Number(match[3] ?? 0)}`;
  };
  const candidate = normalizeRelease(version);
  const specifier = requirement.trim();
  if (!candidate || !specifier || specifier === '*') return specifier === '*';
  if (specifier.startsWith('==='))
    return version.toLowerCase() === specifier.slice(3).trim().toLowerCase();

  const clauses = specifier.split(',').map((item) => item.trim());
  const normalized: string[] = [];
  for (const clause of clauses) {
    if (!clause) return false;
    const wildcard = /^(==|!=)\s*(\d+(?:\.\d+){0,2})\.\*$/u.exec(clause);
    if (wildcard?.[1] && wildcard[2]) {
      const prefix = wildcard[2]
        .split('.')
        .map((part) => String(Number(part)))
        .join('.');
      normalized.push(`${wildcard[1] === '!=' ? '!=' : ''}${prefix}.x`);
      continue;
    }
    const compatible = /^~=\s*(\d+(?:\.\d+){0,2})$/u.exec(clause);
    if (compatible?.[1]) {
      const release = compatible[1].split('.').map(Number);
      if (release.length < 2) return false;
      const lower = normalizeRelease(compatible[1]);
      const upper =
        release.length === 2
          ? `${(release[0] ?? 0) + 1}.0.0`
          : `${release[0] ?? 0}.${(release[1] ?? 0) + 1}.0`;
      if (!lower) return false;
      normalized.push(`>=${lower}`, `<${upper}`);
      continue;
    }
    const comparison = /^(===|==|!=|>=|<=|>|<|=)?\s*(\d+(?:\.\d+){0,2})$/u.exec(
      clause
    );
    if (comparison?.[2]) {
      const expected = normalizeRelease(comparison[2]);
      if (!expected) return false;
      const operator = comparison[1] ?? '=';
      if (operator === '===' || operator === '==') {
        if (candidate !== expected) return false;
      } else {
        normalized.push(`${operator}${expected}`);
      }
      continue;
    }
    // Poetry also accepts PEP 440-compatible range operators such as ^ and ~;
    // semver can evaluate those only for the stable release versions accepted
    // above. Unknown syntax stays unresolved instead of guessing an edge.
    const semverRange = semver.validRange(clause);
    if (!semverRange) return false;
    normalized.push(semverRange);
  }
  return normalized.every((range) => semver.satisfies(candidate, range));
}

function cargoDependencyDeclarations(
  manifest: RecordValue,
  module: string,
  workspaceDependencies: RecordValue,
  warnings: string[],
  sourcePath: string
): CargoDependencyDeclaration[] {
  const result: CargoDependencyDeclaration[] = [];
  const readTable = (
    table: unknown,
    section: DependencyEdge['section'],
    target?: string
  ): void => {
    for (const [alias, raw] of Object.entries(asRecord(table) ?? {})) {
      const local = asRecord(raw);
      const inherited =
        local?.workspace === true
          ? asRecord(workspaceDependencies[alias])
          : undefined;
      const inheritedFeatures = Array.isArray(inherited?.features)
        ? inherited.features
        : [];
      const localFeatures = Array.isArray(local?.features)
        ? local.features
        : [];
      const spec: RecordValue = {
        ...(inherited ?? {}),
        ...(local ?? {}),
        features: [...inheritedFeatures, ...localFeatures]
      };
      if (local?.workspace === true && !inherited) {
        warnings.push(
          `cargo-workspace-dependency-unavailable:${sourcePath}:${alias}`
        );
        continue;
      }
      const packageName =
        typeof spec.package === 'string' ? spec.package : alias;
      if (!/^[A-Za-z0-9_-]{1,256}$/u.test(packageName)) {
        warnings.push(`cargo-dependency-identity-invalid:${sourcePath}`);
        continue;
      }
      const rawVersion = typeof raw === 'string' ? raw : spec.version;
      const requirement =
        typeof rawVersion === 'string' && rawVersion.length <= 256
          ? rawVersion
          : '*';
      let dependencyModule: string | undefined;
      if (typeof spec.path === 'string') {
        const dependencyBase = local?.workspace === true ? '' : module;
        const normalized = path.posix.normalize(
          path.posix.join(
            dependencyBase || '.',
            spec.path.replaceAll('\\', '/')
          )
        );
        if (
          path.posix.isAbsolute(spec.path) ||
          normalized === '..' ||
          normalized.startsWith('../') ||
          normalized.includes('\0')
        ) {
          warnings.push(
            `cargo-path-dependency-outside-project:${sourcePath}:${alias}`
          );
          continue;
        } else dependencyModule = normalized === '.' ? 'root' : normalized;
      }
      const requestedFeatures = Array.isArray(spec.features)
        ? spec.features
            .filter(
              (feature): feature is string =>
                typeof feature === 'string' &&
                /^[A-Za-z0-9_-]{1,128}$/u.test(feature)
            )
            .sort()
        : [];
      result.push({
        name: packageName,
        alias,
        requirement,
        section: spec.optional === true ? 'optionalDependency' : section,
        ...(dependencyModule !== undefined ? { module: dependencyModule } : {}),
        ...(target ? { target } : {}),
        ...(requestedFeatures.length ? { requestedFeatures } : {})
      });
    }
  };
  for (const [key, section] of [
    ['dependencies', 'dependency'],
    ['dev-dependencies', 'devDependency'],
    ['build-dependencies', 'dependency']
  ] as const)
    readTable(manifest[key], section);
  for (const [target, value] of Object.entries(
    asRecord(manifest.target) ?? {}
  )) {
    if (target.length > 512) {
      warnings.push(`cargo-target-context-over-budget:${sourcePath}`);
      continue;
    }
    const targetTable = asRecord(value);
    if (!targetTable) {
      warnings.push(`cargo-target-context-invalid:${sourcePath}`);
      continue;
    }
    for (const [key, section] of [
      ['dependencies', 'dependency'],
      ['dev-dependencies', 'devDependency'],
      ['build-dependencies', 'dependency']
    ] as const)
      readTable(targetTable[key], section, target);
  }
  return result;
}

async function cargoManifestPaths(
  root: string,
  fileSource: DependencyFileSource | undefined,
  warnings: string[]
): Promise<string[]> {
  if (fileSource) {
    const paths = fileSource.files
      .filter((file) => path.posix.basename(file) === 'Cargo.toml')
      .sort();
    if (paths.length > maximumCargoWorkspaceManifests)
      warnings.push('cargo-workspace-manifest-budget-exceeded');
    return paths.slice(0, maximumCargoWorkspaceManifests);
  }
  const pending: Array<{ directory: string; depth: number }> = [
    { directory: '', depth: 0 }
  ];
  const paths: string[] = [];
  let entries = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) continue;
    if (current.depth > 32) {
      warnings.push('cargo-workspace-depth-budget-exceeded');
      continue;
    }
    let children: Dirent[];
    try {
      children = await readdir(path.join(root, current.directory), {
        withFileTypes: true
      });
    } catch {
      warnings.push('cargo-workspace-directory-unavailable');
      continue;
    }
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      if (++entries > maximumComposerWorkspaceEntries) {
        warnings.push('cargo-workspace-entry-budget-exceeded');
        return paths.sort();
      }
      const relative = current.directory
        ? `${current.directory}/${child.name}`
        : child.name;
      if (
        child.isDirectory() &&
        !child.isSymbolicLink() &&
        !['.git', 'node_modules', 'vendor', 'target', 'dist', 'build'].includes(
          child.name
        )
      )
        pending.push({ directory: relative, depth: current.depth + 1 });
      else if (child.isFile() && child.name === 'Cargo.toml') {
        paths.push(relative);
        if (paths.length >= maximumCargoWorkspaceManifests) {
          warnings.push('cargo-workspace-manifest-budget-exceeded');
          return paths.sort();
        }
      }
    }
  }
  return paths.sort();
}

function fromGradleLock(text: string): LockedPackage[] {
  const output: LockedPackage[] = [];
  for (const line of text.split(/\r?\n/u)) {
    const match = line
      .trim()
      .match(/^([^:#\s]+):([^:#\s]+):([^\s=]+)(?:=[^\s]+)?(?:\s+#.*)?$/u);
    if (match?.[1] && match[2] && match[3] && exact(match[3]))
      output.push({
        name: `${match[1]}:${match[2]}`,
        version: match[3],
        ecosystem: 'Maven',
        source: 'gradle.lockfile'
      });
  }
  return output;
}

function fromMavenDependencyTree(
  text: string,
  warnings: string[]
): LockedPackage[] {
  const output: LockedPackage[] = [];
  const stack: Array<LockedPackage | undefined> = [];
  for (const line of text.split(/\r?\n/u)) {
    const rawInfo = line.match(/^\s*\[INFO\](.*)$/u)?.[1];
    if (rawInfo === undefined) continue;
    const info = rawInfo.startsWith(' ') ? rawInfo.slice(1) : rawInfo;
    const marker = info.search(/[+\\]-\s/u);
    if (marker < 0) continue;
    const prefix = info.slice(0, marker);
    const depth = mavenTreeDepth(prefix);
    if (depth === undefined) {
      warnings.push('maven-tree-layout-unresolved');
      continue;
    }
    let coordinateText = info.slice(marker + 2).trim();
    let optional = false;
    const annotations: string[] = [];
    while (coordinateText.endsWith(')')) {
      const annotationStart = coordinateText.lastIndexOf(' (');
      if (annotationStart < 0) break;
      annotations.unshift(coordinateText.slice(annotationStart + 2, -1));
      coordinateText = coordinateText.slice(0, annotationStart).trimEnd();
    }
    let annotationsValid = true;
    for (const annotation of annotations) {
      if (annotation.toLowerCase() === 'optional') optional = true;
      else if (!/^version managed from \S+$/iu.test(annotation))
        annotationsValid = false;
    }
    const parts = coordinateText.split(':');
    if (
      !annotationsValid ||
      (parts.length !== 5 && parts.length !== 6) ||
      !parts[0] ||
      !parts[1] ||
      !parts[2] ||
      !parts[3]
    ) {
      warnings.push('maven-tree-coordinate-unresolved');
      continue;
    }
    if (/\bomitted for conflict\b/iu.test(coordinateText)) {
      warnings.push('maven-tree-conflict-resolution-unavailable');
      continue;
    }
    const hasClassifier = parts.length === 6;
    const packageType = parts[2];
    const classifier = hasClassifier ? parts[3] : undefined;
    const version = hasClassifier ? parts[4] : parts[3];
    const scope = (hasClassifier ? parts[5] : parts[4])?.toLowerCase();
    if (
      !exact(parts[0]) ||
      !exact(parts[1]) ||
      !exact(packageType) ||
      (hasClassifier && !exact(classifier)) ||
      !exact(version) ||
      /[${}]/u.test(version) ||
      !scope ||
      !['compile', 'provided', 'runtime', 'test', 'system', 'import'].includes(
        scope
      )
    ) {
      warnings.push('maven-tree-version-unresolved');
      continue;
    }
    const section: DependencyEdge['section'] = optional
      ? 'optionalDependency'
      : scope === 'test' || scope === 'provided'
        ? 'devDependency'
        : 'dependency';
    const item: LockedPackage = {
      name: `${parts[0]}:${parts[1]}`,
      version,
      ecosystem: 'Maven',
      source: 'maven-dependency-tree.txt',
      packageType,
      ...(classifier ? { classifier } : {}),
      ...(optional ? { optional: true } : {}),
      development: section === 'devDependency',
      direct: depth === 1,
      dependencies: []
    };
    const parent = depth === 1 ? undefined : stack[depth - 1];
    if (depth > 1 && !parent) {
      warnings.push('maven-tree-parent-edge-unresolved');
      continue;
    }
    const mavenPathComponent = `${item.name}@${item.version}:${packageType}:${classifier ?? ''}`;
    item.installPath = parent
      ? `${parent.installPath}/${mavenPathComponent}`
      : `maven-tree:${mavenPathComponent}`;
    if (parent) {
      parent.dependencies?.push({
        name: item.name,
        requirement: item.version,
        section
      });
    }
    stack[depth] = item;
    stack.length = depth + 1;
    output.push(item);
  }
  return output;
}

function mavenTreeDepth(prefix: string): number | undefined {
  if (!prefix) return 1;
  if (prefix.length % 3 !== 0) return undefined;
  if (!/^(?:(?:\| {2})|(?: {3}))+$/u.test(prefix)) return undefined;
  return 1 + prefix.length / 3;
}

/** Parses Maven/Gradle exported resolved graphs without invoking build tooling. */
function fromJavaDependencyGraph(
  value: unknown,
  ecosystem: 'Maven',
  source: 'maven-dependency-tree.json' | 'gradle-dependencies.json',
  warnings: string[]
): LockedPackage[] {
  const record = (item: unknown): Record<string, unknown> | undefined =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? (item as Record<string, unknown>)
      : undefined;
  const document = record(value);
  const roots = Array.isArray(value)
    ? value
    : Array.isArray(document?.modules)
      ? document.modules
      : document
        ? [document]
        : [];
  if (roots.length === 0) {
    warnings.push(`java-export-invalid:${source}`);
    return [];
  }

  const output: LockedPackage[] = [];
  const maxPackages = 100_000;
  const maxDepth = 512;
  for (const [rootIndex, rootValue] of roots.entries()) {
    const root = record(rootValue);
    if (!root) {
      warnings.push(`java-export-module-invalid:${source}`);
      continue;
    }
    const rootIdentity = [
      root.groupId ?? root.group ?? '',
      root.artifactId ?? root.module ?? root.name ?? '',
      root.version ?? ''
    ].join(':');
    const module = `module-${createHash('sha256')
      .update(`${source}\0${rootIdentity}\0${rootIndex}`)
      .digest('hex')
      .slice(0, 16)}`;
    const rootChildren = root.children ?? root.dependencies;
    if (rootChildren === undefined) {
      warnings.push(`java-export-edges-unavailable:${source}`);
      continue;
    }
    if (!Array.isArray(rootChildren)) {
      warnings.push(`java-export-edges-invalid:${source}`);
      continue;
    }
    if (rootChildren.length > maxPackages) {
      warnings.push(`java-export-package-budget-exceeded:${source}`);
    }
    const queue: Array<{
      value: unknown;
      parent?: LockedPackage;
      depth: number;
    }> = rootChildren
      .slice(0, maxPackages)
      .map((child) => ({ value: child, depth: 1 }));
    const instances = new Map<string, LockedPackage>();
    let visited = 0;
    for (let cursor = 0; cursor < queue.length; cursor++) {
      const item = queue[cursor];
      if (!item) continue;
      if (++visited > maxPackages) {
        warnings.push(`java-export-package-budget-exceeded:${source}`);
        break;
      }
      if (item.depth > maxDepth) {
        warnings.push(`java-export-depth-budget-exceeded:${source}`);
        break;
      }
      if (output.length >= maxPackages) {
        warnings.push(`java-export-package-budget-exceeded:${source}`);
        break;
      }
      const dependency = record(item.value);
      if (!dependency) {
        warnings.push(`java-export-dependency-invalid:${source}`);
        continue;
      }
      const group = dependency.groupId ?? dependency.group;
      const artifact =
        dependency.artifactId ?? dependency.module ?? dependency.name;
      const version = dependency.version;
      const packageType = dependency.type ?? 'jar';
      const classifier = dependency.classifier;
      const isValidName = (part: unknown): part is string =>
        typeof part === 'string' &&
        part.length > 0 &&
        part.length <= 512 &&
        /^[A-Za-z0-9_.-]+$/u.test(part);
      if (
        !isValidName(group) ||
        !isValidName(artifact) ||
        !exact(version) ||
        version.length > 256 ||
        /[${}]/u.test(version) ||
        !isValidName(packageType) ||
        (classifier !== undefined && !isValidName(classifier))
      ) {
        warnings.push(`java-export-coordinate-unresolved:${source}`);
        continue;
      }
      if (dependency.omitted === true) {
        warnings.push(`java-export-conflict-omitted:${source}`);
        continue;
      }
      const scope =
        typeof dependency.scope === 'string'
          ? dependency.scope.toLowerCase()
          : 'compile';
      const section: DependencyEdge['section'] =
        dependency.optional === true
          ? 'optionalDependency'
          : scope === 'test' || scope === 'provided'
            ? 'devDependency'
            : 'dependency';
      const coordinate = `${group}:${artifact}@${version}:${packageType}:${classifier ?? ''}`;
      const key = `${module}\0${coordinate}`;
      let resolved = instances.get(key);
      if (!resolved) {
        resolved = {
          name: `${group}:${artifact}`,
          version,
          ecosystem,
          source,
          module,
          packageType,
          ...(classifier ? { classifier } : {}),
          installPath: `java:${module}/${coordinate}`,
          direct: item.depth === 1,
          development: section === 'devDependency',
          dependencies: []
        };
        instances.set(key, resolved);
        output.push(resolved);
        if (item.parent) {
          item.parent.dependencies?.push({
            name: resolved.name,
            requirement: resolved.version,
            section,
            module
          });
        }
      } else if (item.parent) {
        item.parent.dependencies?.push({
          name: resolved.name,
          requirement: resolved.version,
          section,
          module
        });
      }
      const children = dependency.children ?? dependency.dependencies;
      if (children === undefined) continue;
      if (!Array.isArray(children)) {
        warnings.push(`java-export-edges-invalid:${source}`);
        continue;
      }
      if (queue.length + children.length > maxPackages) {
        warnings.push(`java-export-package-budget-exceeded:${source}`);
      }
      for (const child of children.slice(
        0,
        Math.max(0, maxPackages - queue.length)
      ))
        queue.push({ value: child, parent: resolved, depth: item.depth + 1 });
    }
  }
  return output;
}

/** Read exact, lockfile-resolved identities from supported non-npm ecosystems.
 * Missing or unsupported manifests intentionally produce no guessed identities.
 */
async function readInput(
  root: string,
  relativePath: string,
  fileSource?: DependencyFileSource
): Promise<string | undefined> {
  if (fileSource) {
    if (!fileSource.hasFile(relativePath)) return undefined;
    const text = fileSource.readText(relativePath);
    if (text === undefined)
      throw new Error(`Dependency snapshot has no text for ${relativePath}.`);
    return text;
  }
  try {
    return await readBoundedDependencyText(path.join(root, relativePath));
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'code' in error &&
      error.code === 'ENOENT'
    )
      return undefined;
    throw error;
  }
}

type GoReplacement = {
  module: string;
  version?: string;
};

function parseGoReplacement(value: string): GoReplacement | undefined {
  const match = value.match(
    /^([^\s]+)(?:\s+([^\s]+))?\s+=>\s+([^\s]+)(?:\s+([^\s]+))?$/u
  );
  if (!match?.[1] || !match[3]) return undefined;
  return {
    module: decodeGoModulePath(match[1]),
    ...(match[2] ? { version: match[2].replace(/^v/u, '') } : {})
  };
}

function parseGoMod(
  text: string,
  source: string,
  warnings: string[],
  replacements: GoReplacement[] = []
): LockedPackage[] {
  const module = text.match(/^\s*module\s+(?:"([^"]+)"|([^\s]+))/mu);
  const output: LockedPackage[] = [];
  let inRequire = false;
  let inResolutionDirective = '';
  for (const line of text.split(/\r?\n/u)) {
    const indirect = /\/\/\s*indirect\s*$/u.test(line);
    const trimmed = line.replace(/\/\/.*$/u, '').trim();
    if (!trimmed) continue;
    const directive = trimmed.match(/^(replace|exclude|retract)\s*(.*)$/u);
    if (directive?.[1]) {
      warnings.push(`go-${directive[1]}-resolution-incomplete:${source}`);
      if (directive[1] === 'replace' && directive[2] !== '(') {
        const replacement = parseGoReplacement(directive[2] ?? '');
        if (replacement) replacements.push(replacement);
        else warnings.push(`go-replacement-invalid:${source}`);
      }
      inResolutionDirective = directive[2] === '(' ? directive[1] : '';
      continue;
    }
    if (inResolutionDirective && trimmed === ')') {
      inResolutionDirective = '';
      continue;
    }
    if (inResolutionDirective) {
      if (inResolutionDirective === 'replace') {
        const replacement = parseGoReplacement(trimmed);
        if (replacement) replacements.push(replacement);
        else warnings.push(`go-replacement-invalid:${source}`);
      }
      continue;
    }
    if (/^require\s*\($/u.test(trimmed)) {
      inRequire = true;
      continue;
    }
    if (inRequire && trimmed === ')') {
      inRequire = false;
      continue;
    }
    const single = trimmed.match(
      /^require\s+([^\s]+)\s+([^\s]+)(?:\s+\/\/\s*indirect)?$/u
    );
    const block = inRequire
      ? trimmed.match(/^([^\s]+)\s+([^\s]+)(?:\s+\/\/\s*indirect)?$/u)
      : undefined;
    const match = single ?? block;
    if (!match?.[1] || !match[2]) {
      if (/^(?:require\s+|[A-Za-z0-9_.-]+\/)/u.test(trimmed))
        warnings.push(`go-module-requirement-unresolved:${source}`);
      continue;
    }
    if (!/^v\d[^\s]*$/iu.test(match[2])) {
      warnings.push(`go-module-requirement-unresolved:${source}`);
      continue;
    }
    const moduleName = module?.[1] ?? module?.[2] ?? 'unknown';
    const name = decodeGoModulePath(match[1]);
    output.push({
      name,
      version: match[2],
      ecosystem: 'Go',
      source: `${source}:${moduleName}`,
      installPath: `go:${source}:${moduleName}:${name}@${match[2]}`,
      resolutionConfidence: 'declared-pin',
      direct: !indirect
    });
  }
  markGoReplacedPackages(output, replacements, warnings, source);
  return output;
}

function markGoReplacedPackages(
  packages: LockedPackage[],
  replacements: readonly GoReplacement[],
  warnings: string[],
  source: string
): void {
  type IndexedReplacement = { position: number; replacement: GoReplacement };
  type ReplacementCandidates = {
    anyVersion?: IndexedReplacement;
    versions: Map<string, IndexedReplacement>;
  };
  const byModule = new Map<string, ReplacementCandidates>();
  for (const [position, replacement] of replacements.entries()) {
    let candidates = byModule.get(replacement.module);
    if (!candidates) {
      candidates = { versions: new Map() };
      byModule.set(replacement.module, candidates);
    }
    const indexed = { position, replacement };
    if (replacement.version === undefined) {
      candidates.anyVersion ??= indexed;
    } else if (!candidates.versions.has(replacement.version)) {
      candidates.versions.set(replacement.version, indexed);
    }
  }
  for (const item of packages) {
    const candidates = byModule.get(item.name);
    const exact = candidates?.versions.get(item.version.replace(/^v/u, ''));
    const general = candidates?.anyVersion;
    const replacement =
      exact && general
        ? exact.position < general.position
          ? exact.replacement
          : general.replacement
        : (exact?.replacement ?? general?.replacement);
    if (!replacement) continue;
    item.source = `${source}:replacement-unverified`;
    item.resolutionConfidence = 'unknown';
    warnings.push(`go-replacement-provenance-unverified:${item.name}`);
  }
}

function parseGoWorkspace(text: string): string[] {
  const output = new Set<string>();
  let inUse = false;
  for (const line of text.split(/\r?\n/u)) {
    const clean = line.replace(/\/\/.*$/u, '').trim();
    if (!clean) continue;
    const use = clean.match(/^use\s+(.+)$/u);
    if (use?.[1]) {
      if (use[1] === '(') {
        inUse = true;
        continue;
      }
      output.add(use[1].replace(/^"|"$/gu, ''));
      continue;
    }
    if (inUse && clean === ')') {
      inUse = false;
      continue;
    }
    if (inUse) output.add(clean.replace(/^"|"$/gu, ''));
  }
  return [...output];
}

function decodeGoModulePath(value: string): string {
  return value.replace(/!([a-z])/gu, (_match, letter: string) =>
    letter.toUpperCase()
  );
}

function encodeGoModulePath(value: string): string {
  return value.replace(/[A-Z]/gu, (letter) => `!${letter.toLowerCase()}`);
}

function goModuleReference(
  value: unknown
): { name: string; version: string } | undefined {
  if (typeof value !== 'string' || value.length > 4_096) return undefined;
  const separator = value.lastIndexOf('@');
  if (separator < 1 || separator === value.length - 1) return undefined;
  const name = decodeGoModulePath(value.slice(0, separator));
  const version = value.slice(separator + 1);
  if (!name || !semver.valid(version)) return undefined;
  return { name, version };
}

function resolveGoToolGraph(input: {
  modulesJson: string;
  graphText: string;
  goSums: ReadonlyMap<string, string>;
  sourceGoSums: ReadonlyMap<string, string>;
}): { packages: LockedPackage[]; edges: DependencyEdge[]; warnings: string[] } {
  const records = parseGoModuleJsonStream(input.modulesJson);
  const packages: LockedPackage[] = [];
  const edges: DependencyEdge[] = [];
  const warnings = new Set<string>();
  const identities = new Map<string, LockedPackage | 'root'>();
  const selectedByModule = new Map<string, LockedPackage | 'root'>();
  const selectedVersionByModule = new Map<string, string>();
  const roots: Array<{ name: string; version: string }> = [];

  for (const record of records) {
    const name =
      typeof record.Path === 'string' && record.Path.length <= 2_048
        ? decodeGoModulePath(record.Path)
        : undefined;
    if (!name) {
      warnings.add('go-tool-module-identity-invalid');
      continue;
    }
    const version = typeof record.Version === 'string' ? record.Version : '';
    if (record.Main === true) {
      roots.push({ name, version });
      identities.set(name, 'root');
      selectedByModule.set(name, 'root');
      if (version) identities.set(`${name}@${version}`, 'root');
      continue;
    }
    if (!version || !semver.valid(version)) {
      warnings.add(`go-tool-module-version-invalid:${name}`);
      continue;
    }
    const reference = `${name}@${version}`;
    const escapedReference = `${encodeGoModulePath(name)}@${version}`;
    if (identities.has(reference) || identities.has(escapedReference)) {
      warnings.add(`go-tool-module-duplicate:${name}`);
      continue;
    }
    const replacement = asRecord(record.Replace);
    const replacementPath =
      typeof replacement?.Path === 'string'
        ? decodeGoModulePath(replacement.Path)
        : undefined;
    const replacementVersion =
      typeof replacement?.Version === 'string' ? replacement.Version : '';
    const replaced = replacement !== undefined;
    const replacementIsExternal =
      Boolean(replacementPath) &&
      !path.isAbsolute(replacementPath ?? '') &&
      !replacementPath?.startsWith('.') &&
      !replacementPath?.includes('\\') &&
      !replacementPath?.includes('@') &&
      replacementVersion.length > 0 &&
      semver.valid(replacementVersion) !== null;
    const packageName =
      replaced && replacementIsExternal ? (replacementPath ?? name) : name;
    const packageVersion =
      replaced && replacementIsExternal ? replacementVersion : version;
    const checksumRecord =
      replaced && replacementIsExternal ? replacement : record;
    const goModSumKey = `${encodeGoModulePath(packageName)}@${packageVersion}/go.mod`;
    const capturedGoModSum = input.goSums.get(goModSumKey);
    // `go list -m -json all` does not consistently expose GoModSum. Go may
    // instead write the checksum-db-verified value into the isolated copy's
    // go.sum, so use that only when the JSON record omits the field.
    const goModSum =
      typeof checksumRecord.GoModSum === 'string'
        ? checksumRecord.GoModSum
        : capturedGoModSum;
    const moduleSum =
      typeof checksumRecord.Sum === 'string' ? checksumRecord.Sum : undefined;
    const moduleSumKey = `${encodeGoModulePath(packageName)}@${packageVersion}`;
    const capturedModuleSum = input.goSums.get(moduleSumKey);
    const sourceGoModSum = input.sourceGoSums.get(goModSumKey);
    const sourceModuleSum = input.sourceGoSums.get(moduleSumKey);
    const sourceChecksumsAgree =
      (sourceGoModSum === undefined || sourceGoModSum === goModSum) &&
      (sourceModuleSum === undefined ||
        (moduleSum !== undefined && sourceModuleSum === moduleSum));
    const validGoModSum =
      goModSum !== undefined &&
      /^h1:[A-Za-z0-9+/]+={0,2}$/u.test(goModSum) &&
      capturedGoModSum === goModSum &&
      (sourceGoModSum === undefined || sourceGoModSum === goModSum);
    const validModuleSum =
      moduleSum === undefined ||
      (/^h1:[A-Za-z0-9+/]+={0,2}$/u.test(moduleSum) &&
        capturedModuleSum === moduleSum &&
        (sourceModuleSum === undefined || sourceModuleSum === moduleSum));
    const trusted =
      validGoModSum &&
      validModuleSum &&
      sourceChecksumsAgree &&
      (!replaced || replacementIsExternal);
    const source = trusted
      ? replaced
        ? 'go-tool:mvs-replacement-sumdb-verified'
        : 'go-tool:mvs-sumdb-verified'
      : 'go-tool:mvs-provenance-unverified';
    const item: LockedPackage = {
      name: packageName,
      version: packageVersion,
      ecosystem: 'Go',
      source,
      resolutionConfidence: trusted ? 'lockfile' : 'unknown',
      installPath: `go:mvs:${name}@${version}${replaced ? `=>${packageName}@${packageVersion}` : ''}`,
      direct: record.Indirect !== true,
      ...(moduleSum ? { integrity: moduleSum } : {})
    };
    packages.push(item);
    identities.set(reference, item);
    identities.set(escapedReference, item);
    identities.set(`${packageName}@${packageVersion}`, item);
    identities.set(
      `${encodeGoModulePath(packageName)}@${packageVersion}`,
      item
    );
    selectedByModule.set(name, item);
    selectedVersionByModule.set(name, version);
    if (replaced && replacementIsExternal && packageName !== name) {
      selectedByModule.set(packageName, item);
      selectedVersionByModule.set(packageName, packageVersion);
    }
    if (replaced && !replacementIsExternal)
      warnings.add(`go-replacement-provenance-unverified:${name}`);
    if (!validGoModSum)
      warnings.add(
        `go-checksum-database-unverified:${packageName}@${packageVersion}`
      );
    if (!validModuleSum)
      warnings.add(`go-checksum-mismatch:${packageName}@${packageVersion}`);
    if (!sourceChecksumsAgree)
      warnings.add(
        `go-checksum-source-mismatch:${packageName}@${packageVersion}`
      );
    if (Array.isArray(record.Retracted) && record.Retracted.length > 0)
      warnings.add(`go-module-retracted:${name}@${version}`);
    if (typeof record.Deprecated === 'string' && record.Deprecated.length > 0)
      warnings.add(`go-module-deprecated:${name}@${version}`);
  }

  if (roots.length === 0) warnings.add('go-tool-main-module-missing');
  const rootNames = new Set(roots.map((root) => root.name));
  let graphLines = 0;
  for (const line of input.graphText.split(/\r?\n/u)) {
    const clean = line.trim();
    if (!clean) continue;
    graphLines++;
    const fields = clean.split(/\s+/u);
    // Newer Go versions represent the `go` directive and selected toolchain
    // as pseudo-nodes in `go mod graph`; they are not package dependencies.
    if (
      fields.some(
        (field) =>
          /^go@\d+\.\d+(?:\.\d+)?$/u.test(field) ||
          /^toolchain@go\d+\.\d+(?:\.\d+)?$/u.test(field)
      )
    )
      continue;
    if (fields.length === 3 && fields[1] === '=>') {
      const original = goModuleReference(fields[0]);
      const replacement = goModuleReference(fields[2]);
      const originalIdentity = original
        ? identities.get(`${original.name}@${original.version}`)
        : undefined;
      const replacementIdentity = replacement
        ? identities.get(`${replacement.name}@${replacement.version}`)
        : undefined;
      if (
        !originalIdentity ||
        !replacementIdentity ||
        originalIdentity !== replacementIdentity
      )
        warnings.add('go-module-replacement-graph-unresolved');
      continue;
    }
    if (fields.length !== 2 || fields.some((field) => field.includes('=>'))) {
      warnings.add('go-module-graph-replacement-or-record-unsupported');
      continue;
    }
    const rawFrom = fields[0] ?? '';
    const from = goModuleReference(rawFrom);
    const to = goModuleReference(fields[1]);
    const rootFrom = !from && rootNames.has(decodeGoModulePath(rawFrom));
    if (
      from &&
      selectedVersionByModule.has(from.name) &&
      selectedVersionByModule.get(from.name) !== from.version
    ) {
      // `go mod graph` includes requirements from older, unselected versions.
      // Their outgoing edges are not part of the resolved MVS graph.
      continue;
    }
    if ((!from && !rootFrom) || !to) {
      warnings.add('go-module-graph-record-invalid');
      continue;
    }
    const fromIdentity = rootFrom
      ? 'root'
      : (identities.get(`${from?.name}@${from?.version}`) ??
        (from ? selectedByModule.get(from.name) : undefined) ??
        (from && rootNames.has(from.name) ? 'root' : undefined));
    const target =
      identities.get(`${to.name}@${to.version}`) ??
      selectedByModule.get(to.name);
    if (!fromIdentity || !target) {
      warnings.add('go-module-graph-reference-unresolved');
      continue;
    }
    if (target === 'root') continue;
    const targetIdentity = identity(target);
    if (fromIdentity === 'root') {
      target.direct = true;
      continue;
    }
    const sourceIdentity = identity(fromIdentity).id;
    edges.push({
      from: sourceIdentity,
      to: targetIdentity.id,
      name: target.name,
      requirement: target.version,
      section: 'dependency'
    });
  }
  if (graphLines === 0) warnings.add('go-module-graph-empty');
  const uniqueEdges = new Map<string, DependencyEdge>();
  for (const edge of edges) uniqueEdges.set(`${edge.from}\0${edge.to}`, edge);
  return {
    packages,
    edges: [...uniqueEdges.values()],
    warnings: [...warnings].sort()
  };
}

function goSumChecksums(text: string, warnings: string[]): Map<string, string> {
  const checksums = new Map<string, string>();
  const conflicting = new Set<string>();
  for (const line of text.split(/\r?\n/u)) {
    const fields = line.trim().split(/\s+/u);
    if (fields.length !== 3 || fields[1]?.endsWith('/go.mod')) continue;
    const match = fields[1]?.match(/^(v?\d[^\s]*)$/u);
    const checksum = fields[2] ?? '';
    const encoded = /^h1:([A-Za-z0-9+/]+={0,2})$/u.exec(checksum)?.[1];
    if (!fields[0] || !match?.[1] || !encoded) continue;
    const digest = Buffer.from(encoded, 'base64');
    if (digest.length !== 32 || digest.toString('base64') !== encoded) {
      warnings.push('go-checksum-format-invalid');
      continue;
    }
    const key = `${decodeGoModulePath(fields[0])}@${match[1].replace(/^v/u, '')}`;
    if (conflicting.has(key)) continue;
    const prior = checksums.get(key);
    if (prior && prior !== checksum) {
      checksums.delete(key);
      conflicting.add(key);
      warnings.push(`go-checksum-conflict:${key}`);
      continue;
    }
    checksums.set(key, checksum);
  }
  if (checksums.size > 0)
    warnings.push('go-checksum-database-status-unverified');
  return checksums;
}

function fromGoVendorModules(
  text: string,
  warnings: string[]
): LockedPackage[] {
  const output: LockedPackage[] = [];
  let current:
    | { name: string; version: string; explicit: boolean; replaced: boolean }
    | undefined;
  const flush = (): void => {
    if (!current) return;
    if (current.version === 'unknown') {
      current = undefined;
      return;
    }
    const source = current.replaced
      ? 'vendor/modules.txt:replacement-unverified'
      : 'vendor/modules.txt';
    output.push({
      name: current.name,
      version: current.version,
      ecosystem: 'Go',
      source,
      installPath: `go:vendor:${current.name}@${current.version}`,
      resolutionConfidence: current.replaced ? 'unknown' : 'lockfile',
      direct: current.explicit
    });
    if (current.replaced)
      warnings.push('go-vendor-replacement-provenance-unverified');
  };
  for (const line of text.split(/\r?\n/u)) {
    const header = line.match(
      /^#\s+([^\s]+)\s+(v\d+[^\s]*)(?:\s+=>\s+.*)?\s*$/u
    );
    if (header?.[1] && header[2]) {
      flush();
      current = {
        name: decodeGoModulePath(header[1]),
        version: header[2],
        explicit: false,
        replaced: /\s=>\s/u.test(line)
      };
      continue;
    }
    const replacementOnly = line.match(/^#\s+([^\s]+)\s+=>\s+.*$/u);
    if (replacementOnly?.[1]) {
      flush();
      current = {
        name: decodeGoModulePath(replacementOnly[1]),
        version: 'unknown',
        explicit: false,
        replaced: true
      };
      warnings.push('go-vendor-replacement-version-unresolved');
      continue;
    }
    if (current && /^##\s+explicit(?:;|\s|$)/u.test(line))
      current.explicit = true;
  }
  flush();
  return output;
}

/** Extracts Go import declarations without interpreting comments or string contents. */
function parseGoImports(source: string): {
  imports: string[];
  complete: boolean;
} {
  type Token = { kind: 'word' | 'string' | 'symbol'; value: string };
  const tokens: Token[] = [];
  let complete = true;
  for (let index = 0; index < source.length;) {
    const current = source[index] ?? '';
    const next = source[index + 1] ?? '';
    if (/\s/u.test(current)) {
      index++;
      continue;
    }
    if (current === '/' && next === '/') {
      index += 2;
      while (index < source.length && source[index] !== '\n') index++;
      continue;
    }
    if (current === '/' && next === '*') {
      index += 2;
      const end = source.indexOf('*/', index);
      if (end < 0) return { imports: [], complete: false };
      index = end + 2;
      continue;
    }
    if (current === '"' || current === '`') {
      const quote = current;
      const start = index++;
      let escaped = false;
      while (index < source.length) {
        const character = source[index] ?? '';
        if (quote === '"' && !escaped && character === '"') break;
        if (quote === '`' && character === '`') break;
        if (quote === '"' && !escaped && character === '\\') {
          escaped = true;
          index++;
          continue;
        }
        escaped = false;
        if (quote === '`' && character === '\0') complete = false;
        index++;
      }
      if (index >= source.length) return { imports: [], complete: false };
      const literal = source.slice(start, index + 1);
      let value: string;
      if (quote === '`') value = literal.slice(1, -1);
      else {
        try {
          value = JSON.parse(literal) as string;
        } catch {
          complete = false;
          value = '';
        }
      }
      tokens.push({ kind: 'string', value });
      index++;
      continue;
    }
    if (current === "'") {
      index++;
      let escaped = false;
      while (index < source.length) {
        const character = source[index] ?? '';
        if (!escaped && character === "'") break;
        if (!escaped && character === '\\') escaped = true;
        else escaped = false;
        index++;
      }
      if (index >= source.length) return { imports: [], complete: false };
      index++;
      continue;
    }
    if (/[A-Za-z_]/u.test(current)) {
      const start = index++;
      while (index < source.length && /[A-Za-z0-9_]/u.test(source[index] ?? ''))
        index++;
      tokens.push({ kind: 'word', value: source.slice(start, index) });
      continue;
    }
    if (current === '(' || current === ')' || current === '.')
      tokens.push({ kind: 'symbol', value: current });
    index++;
  }
  const imports: string[] = [];
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]?.kind !== 'word' || tokens[index]?.value !== 'import')
      continue;
    const next = tokens[index + 1];
    if (next?.kind === 'string') {
      if (validGoImportPath(next.value)) imports.push(next.value);
      else complete = false;
      index++;
      continue;
    }
    if (next?.kind === 'symbol' && next.value === '(') {
      let foundClose = false;
      for (index += 2; index < tokens.length; index++) {
        const token = tokens[index];
        if (token?.kind === 'symbol' && token.value === ')') {
          foundClose = true;
          break;
        }
        if (token?.kind !== 'string') continue;
        if (validGoImportPath(token.value)) imports.push(token.value);
        else complete = false;
      }
      if (!foundClose) complete = false;
      continue;
    }
    const aliasedPath =
      (next?.kind === 'word' ||
        (next?.kind === 'symbol' && next.value === '.')) &&
      tokens[index + 2]?.kind === 'string'
        ? tokens[index + 2]
        : undefined;
    if (aliasedPath?.kind === 'string') {
      if (validGoImportPath(aliasedPath.value)) imports.push(aliasedPath.value);
      else complete = false;
      index += 2;
      continue;
    }
    complete = false;
  }
  return { imports: [...new Set(imports)], complete };
}

function validGoImportPath(value: string): boolean {
  return value.length > 0 && value.length <= 2_048 && !/[\s\0\\]/u.test(value);
}

function goVendorPath(module: string): string {
  return module.replace(/[A-Z]/gu, (letter) => `!${letter.toLowerCase()}`);
}

type PathPrefixNode<T> = {
  value?: T;
  children: Map<string, PathPrefixNode<T>>;
};

function pathPrefixIndex<T>(
  entries: readonly { prefix: string; value: T }[]
): PathPrefixNode<T> {
  const root: PathPrefixNode<T> = { children: new Map() };
  for (const entry of entries) {
    let current = root;
    for (const segment of entry.prefix.split('/')) {
      let child = current.children.get(segment);
      if (!child) {
        child = { children: new Map() };
        current.children.set(segment, child);
      }
      current = child;
    }
    current.value ??= entry.value;
  }
  return root;
}

function longestPathPrefix<T>(
  index: PathPrefixNode<T>,
  value: string
): T | undefined {
  let current = index;
  let match = current.value;
  for (const segment of value.split('/')) {
    const child = current.children.get(segment);
    if (!child) break;
    current = child;
    if (current.value !== undefined) match = current.value;
  }
  return match;
}

function longestGoModuleMatch<T extends { name: string }>(
  importPath: string,
  moduleIndex: PathPrefixNode<T>
): T | undefined {
  return longestPathPrefix(moduleIndex, decodeGoModulePath(importPath));
}

function addGoVendorImportGraph(
  packages: LockedPackage[],
  fileSource: DependencyFileSource | undefined,
  warnings: string[]
): void {
  if (!fileSource) {
    warnings.push('go-vendor-transitive-edges-unresolved');
    return;
  }
  const sourceFiles = fileSource.files
    .filter((file) => file.endsWith('.go'))
    .sort();
  if (sourceFiles.length === 0) {
    warnings.push('go-vendor-transitive-edges-unresolved');
    return;
  }
  let complete = sourceFiles.length <= maximumGoSourceFiles;
  if (!complete) warnings.push('go-source-file-budget-exceeded');
  let totalBytes = 0;
  const boundedFiles = sourceFiles.slice(0, maximumGoSourceFiles);
  const modules = packages.filter(
    (item) => item.ecosystem === 'Go' && item.resolutionConfidence !== 'unknown'
  );
  const modulesByName = new Map(modules.map((item) => [item.name, item]));
  const moduleIndex = pathPrefixIndex(
    modules.map((item) => ({ prefix: item.name, value: item }))
  );
  const vendorIndex = pathPrefixIndex(
    modules.map((item) => ({ prefix: goVendorPath(item.name), value: item }))
  );
  const importsByModule = new Map<LockedPackage, Set<string>>();
  const rootImports = new Set<string>();
  const seenVendorModules = new Set<LockedPackage>();
  for (const file of boundedFiles) {
    const normalized = path.posix.normalize(file);
    if (
      normalized !== file ||
      path.posix.isAbsolute(file) ||
      file.includes('\\') ||
      file === '..' ||
      file.startsWith('../')
    ) {
      complete = false;
      warnings.push('go-source-path-invalid');
      continue;
    }
    let source: string | undefined;
    try {
      source = fileSource.readText(file);
    } catch {
      complete = false;
      warnings.push(`go-source-unavailable:${file}`);
      continue;
    }
    if (source === undefined) {
      complete = false;
      warnings.push(`go-source-unavailable:${file}`);
      continue;
    }
    const bytes = Buffer.byteLength(source, 'utf8');
    totalBytes += bytes;
    if (bytes > maximumGoSourceFileBytes || totalBytes > maximumGoSourceBytes) {
      complete = false;
      warnings.push('go-source-byte-budget-exceeded');
      break;
    }
    if (/^\s*\/\/\s*(?:go:build|\+build)\b/mu.test(source)) {
      complete = false;
      warnings.push('go-source-build-constraints-unselected');
    }
    const parsed = parseGoImports(source);
    if (!parsed.complete) {
      complete = false;
      warnings.push(`go-source-imports-incomplete:${file}`);
    }
    const vendorPrefix = 'vendor/';
    const vendorRelative = file.startsWith(vendorPrefix)
      ? file.slice(vendorPrefix.length)
      : undefined;
    const owner = vendorRelative
      ? longestPathPrefix(vendorIndex, vendorRelative)
      : undefined;
    if (owner) seenVendorModules.add(owner);
    const dependencies = owner
      ? (importsByModule.get(owner) ?? new Set<string>())
      : rootImports;
    for (const importPath of parsed.imports) {
      const target = longestGoModuleMatch(importPath, moduleIndex);
      if (!target) {
        if (importPath.split('/')[0]?.includes('.')) {
          complete = false;
          warnings.push(
            `go-import-not-in-vendor:${decodeGoModulePath(importPath)}`
          );
        }
        continue;
      }
      if (owner?.name === target.name) continue;
      dependencies.add(target.name);
      if (owner) importsByModule.set(owner, dependencies);
      else target.direct = true;
    }
  }
  for (const item of modules) {
    const imported = importsByModule.get(item);
    if (!imported) continue;
    item.dependencies = [...imported]
      .map((name) => {
        const target = modulesByName.get(name);
        return target
          ? {
              name: target.name,
              requirement: target.version,
              section: 'dependency' as const
            }
          : undefined;
      })
      .filter((dependency) => dependency !== undefined);
  }
  if (seenVendorModules.size < modules.length) {
    complete = false;
    warnings.push('go-vendor-source-coverage-incomplete');
  }
  if (!complete) warnings.push('go-vendor-transitive-edges-unresolved');
}

type PythonRootRequirement = {
  name: string;
  requirement: string;
  section: DependencyEdge['section'];
  module?: string;
  marker?: string;
  extras?: string[];
};

function parsePythonRequirement(
  value: unknown,
  section: DependencyEdge['section'],
  optionalGroup?: string,
  module?: string
): PythonRootRequirement | undefined {
  if (typeof value !== 'string' || value.length > 4_096) return undefined;
  const text = value.trim();
  const match = text.match(
    /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([^\]]+)\])?(.*)$/u
  );
  if (!match?.[1]) return undefined;
  const tail = match[3] ?? '';
  const markerIndex = tail.indexOf(';');
  const requirement = (
    markerIndex < 0 ? tail : tail.slice(0, markerIndex)
  ).trim();
  const marker =
    markerIndex < 0 ? undefined : tail.slice(markerIndex + 1).trim();
  const extras = [
    ...(match[2]?.split(',').map((extra) => extra.trim()) ?? []),
    ...(optionalGroup ? [optionalGroup] : [])
  ]
    .filter(Boolean)
    .map((extra) => extra.toLowerCase().replace(/[-_.]+/gu, '-'))
    .sort();
  return {
    name: canonicalPythonName(match[1]),
    requirement: requirement || '*',
    section,
    ...(module ? { module } : {}),
    ...(marker ? { marker } : {}),
    ...(extras.length ? { extras: [...new Set(extras)] } : {})
  };
}

function pythonManifestRequirements(
  value: unknown,
  module?: string
): PythonRootRequirement[] {
  const manifest = asRecord(value);
  if (!manifest) return [];
  const output: PythonRootRequirement[] = [];
  const project = asRecord(manifest.project);
  if (Array.isArray(project?.dependencies)) {
    for (const raw of project.dependencies) {
      const parsed = parsePythonRequirement(
        raw,
        'dependency',
        undefined,
        module
      );
      if (parsed) output.push(parsed);
    }
  }
  const projectOptional = asRecord(project?.['optional-dependencies']);
  for (const [group, dependencies] of Object.entries(projectOptional ?? {})) {
    if (!Array.isArray(dependencies)) continue;
    for (const raw of dependencies) {
      const parsed = parsePythonRequirement(
        raw,
        'optionalDependency',
        group,
        module
      );
      if (parsed) output.push(parsed);
    }
  }

  const poetry = asRecord(asRecord(manifest.tool)?.poetry);
  const poetryDependencies = asRecord(poetry?.dependencies);
  for (const [name, requirement] of Object.entries(poetryDependencies ?? {})) {
    if (name.toLowerCase() === 'python') continue;
    const descriptor = asRecord(requirement);
    const version =
      typeof requirement === 'string'
        ? requirement
        : typeof descriptor?.version === 'string'
          ? descriptor.version
          : '*';
    const parsed = parsePythonRequirement(
      `${name}${version === '*' ? '' : version.startsWith('[') ? version : ` ${version}`}`,
      'dependency',
      undefined,
      module
    );
    if (parsed) {
      if (typeof descriptor?.markers === 'string')
        parsed.marker = descriptor.markers;
      if (Array.isArray(descriptor?.extras))
        parsed.extras = descriptor.extras
          .filter((extra): extra is string => typeof extra === 'string')
          .map((extra) => extra.toLowerCase().replace(/[-_.]+/gu, '-'))
          .sort();
      output.push(parsed);
    }
  }
  const poetryDev = asRecord(poetry?.['dev-dependencies']);
  for (const [name, requirement] of Object.entries(poetryDev ?? {})) {
    const descriptor = asRecord(requirement);
    const version =
      typeof requirement === 'string'
        ? requirement
        : typeof descriptor?.version === 'string'
          ? descriptor.version
          : '*';
    const parsed = parsePythonRequirement(
      `${name}${version === '*' ? '' : ` ${version}`}`,
      'devDependency',
      undefined,
      module
    );
    if (parsed) output.push(parsed);
  }
  const poetryGroups = asRecord(poetry?.group);
  for (const [group, rawGroup] of Object.entries(poetryGroups ?? {})) {
    const dependencies = asRecord(asRecord(rawGroup)?.dependencies);
    const section = /^(?:dev|test|lint|type|docs?)(?:[-_]|$)/iu.test(group)
      ? 'devDependency'
      : 'optionalDependency';
    for (const [name, requirement] of Object.entries(dependencies ?? {})) {
      const descriptor = asRecord(requirement);
      const version =
        typeof requirement === 'string'
          ? requirement
          : typeof descriptor?.version === 'string'
            ? descriptor.version
            : '*';
      const parsed = parsePythonRequirement(
        `${name}${version === '*' ? '' : ` ${version}`}`,
        section,
        section === 'optionalDependency' ? group : undefined,
        module
      );
      if (parsed) output.push(parsed);
    }
  }
  return output;
}

function pythonProjectName(value: unknown): string | undefined {
  const manifest = asRecord(value);
  const project = asRecord(manifest?.project);
  const poetry = asRecord(asRecord(manifest?.tool)?.poetry);
  const raw = project?.name ?? poetry?.name;
  return typeof raw === 'string' && raw.length <= 256
    ? canonicalPythonName(raw)
    : undefined;
}

function pythonWorkspacePatterns(
  value: unknown,
  warnings: string[]
): { members: string[]; exclude: string[] } | undefined {
  const workspace = asRecord(asRecord(asRecord(value)?.tool)?.uv);
  const declaration = asRecord(workspace?.workspace);
  if (!declaration) return undefined;
  const readPatterns = (key: 'members' | 'exclude'): string[] => {
    const raw = declaration[key];
    if (raw === undefined && key === 'exclude') return [];
    if (
      !Array.isArray(raw) ||
      raw.length > maximumPythonWorkspaceManifests ||
      raw.some(
        (pattern) =>
          typeof pattern !== 'string' ||
          pattern.length === 0 ||
          pattern.length > 512 ||
          pattern.includes('\\') ||
          pattern.includes('\0') ||
          path.posix.isAbsolute(pattern) ||
          pattern.split('/').some((part) => part === '..')
      )
    ) {
      warnings.push(`python-workspace-${key}-invalid`);
      return [];
    }
    return raw as string[];
  };
  const members = readPatterns('members');
  const exclude = readPatterns('exclude');
  return { members, exclude };
}

function workspacePatternMatches(
  pattern: string,
  directory: string,
  budget: { used: number; exceeded: boolean }
): boolean {
  const tokens: Array<{ value: string; star: boolean; crossSlash: boolean }> =
    [];
  for (let index = 0; index < pattern.length; index++) {
    if (++budget.used > maximumWorkspaceGlobWork) {
      budget.exceeded = true;
      return false;
    }
    const character = pattern[index] ?? '';
    if (character === '*') {
      const crossSlash = pattern[index + 1] === '*';
      if (crossSlash) index++;
      tokens.push({ value: '*', star: true, crossSlash });
    } else {
      tokens.push({ value: character, star: false, crossSlash: false });
    }
  }
  let previous = new Uint8Array(directory.length + 1);
  previous[0] = 1;
  for (const token of tokens) {
    if (budget.exceeded) return false;
    const current = new Uint8Array(directory.length + 1);
    if (token.star) {
      current[0] = previous[0] ?? 0;
      for (let index = 1; index <= directory.length; index++) {
        if (++budget.used > maximumWorkspaceGlobWork) {
          budget.exceeded = true;
          return false;
        }
        const character = directory[index - 1] ?? '';
        current[index] =
          previous[index] === 1 ||
          (current[index - 1] === 1 && (token.crossSlash || character !== '/'))
            ? 1
            : 0;
      }
    } else {
      for (let index = 1; index <= directory.length; index++) {
        if (++budget.used > maximumWorkspaceGlobWork) {
          budget.exceeded = true;
          return false;
        }
        const character = directory[index - 1] ?? '';
        const matches =
          token.value === '?' ? character !== '/' : token.value === character;
        current[index] = previous[index - 1] === 1 && matches ? 1 : 0;
      }
    }
    previous = current;
  }
  return previous[directory.length] === 1;
}

async function pythonWorkspaceManifestPaths(
  root: string,
  fileSource: DependencyFileSource | undefined,
  warnings: string[]
): Promise<string[]> {
  if (fileSource) {
    const paths = fileSource.files
      .filter(
        (file) =>
          path.posix.basename(file) === 'pyproject.toml' &&
          file !== 'pyproject.toml'
      )
      .sort();
    if (paths.length > maximumPythonWorkspaceManifests)
      warnings.push('python-workspace-manifest-budget-exceeded');
    return paths.slice(0, maximumPythonWorkspaceManifests);
  }
  const pending: Array<{ directory: string; depth: number }> = [
    { directory: '', depth: 0 }
  ];
  const paths: string[] = [];
  let entries = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) continue;
    if (current.depth > 32) {
      warnings.push('python-workspace-depth-budget-exceeded');
      continue;
    }
    let children: Dirent[];
    try {
      children = await readdir(path.join(root, current.directory), {
        withFileTypes: true
      });
    } catch {
      warnings.push('python-workspace-directory-unavailable');
      continue;
    }
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      if (++entries > maximumPythonWorkspaceEntries) {
        warnings.push('python-workspace-entry-budget-exceeded');
        return paths.sort();
      }
      const relative = current.directory
        ? `${current.directory}/${child.name}`
        : child.name;
      if (
        child.isDirectory() &&
        !child.isSymbolicLink() &&
        !['.git', '.venv', 'node_modules', 'vendor', 'dist', 'build'].includes(
          child.name
        )
      ) {
        pending.push({ directory: relative, depth: current.depth + 1 });
      } else if (child.isFile() && child.name === 'pyproject.toml') {
        paths.push(relative);
        if (paths.length >= maximumPythonWorkspaceManifests) {
          warnings.push('python-workspace-manifest-budget-exceeded');
          return paths.sort();
        }
      }
    }
  }
  return paths.sort();
}

function pipRequirementsPackages(
  file: string,
  text: string,
  warnings: string[],
  inheritedSourceKnown = true
): { packages: LockedPackage[]; lockComplete: boolean } {
  const packages: LockedPackage[] = [];
  const logicalLines: string[] = [];
  let current = '';
  let sourceKnown = inheritedSourceKnown;
  const lines = text.split(/\r?\n/u);
  for (const rawLine of lines) {
    let line = rawLine.replace(/\s+#.*$/u, '').trim();
    if (!line || line.startsWith('#')) continue;
    const indexDirective = line.match(
      /^--(?:index-url|extra-index-url)(?:=|\s+)(\S+)/u
    );
    if (indexDirective?.[1]) {
      try {
        const url = new URL(indexDirective[1]);
        if (
          url.protocol !== 'https:' ||
          url.hostname !== 'pypi.org' ||
          !/^\/(?:simple|pypi)(?:\/|$)/u.test(url.pathname) ||
          url.username ||
          url.password ||
          url.search ||
          url.hash ||
          line.startsWith('--extra-index-url')
        )
          sourceKnown = false;
      } catch {
        sourceKnown = false;
      }
      continue;
    }
    if (line.startsWith('-') && !(current && line.startsWith('--hash='))) {
      if (
        /^(?:-r(?:\s|=|\S)|--requirement(?:\s|=)|-c(?:\s|=|\S)|--constraint(?:\s|=))/u.test(
          line
        )
      )
        continue;
      sourceKnown = false;
      warnings.push(`python-requirements-option-unresolved:${file}`);
      continue;
    }
    const continuation = /\\\s*$/u.test(line);
    if (continuation) line = line.replace(/\\\s*$/u, '').trim();
    current = current ? `${current} ${line}` : line;
    if (!continuation) {
      logicalLines.push(current);
      current = '';
    }
  }
  let malformed = false;
  if (current) {
    malformed = true;
    warnings.push(`python-requirements-continuation-incomplete:${file}`);
  }
  const parsedLines: Array<{
    name: string;
    version: string;
    extras: string[];
    marker?: string;
    hashes: string[];
  }> = [];
  for (const logicalLine of logicalLines) {
    const hashMatches = [
      ...logicalLine.matchAll(/--hash=(sha256|sha384|sha512):([A-Fa-f0-9]+)/gu)
    ];
    if (hashMatches.length > 32) {
      malformed = true;
      warnings.push(`python-requirements-hash-budget-exceeded:${file}`);
      continue;
    }
    const hashLengths: Record<string, number> = {
      sha256: 64,
      sha384: 96,
      sha512: 128
    };
    const hashes = hashMatches.map(
      (match) => `${match[1]}:${match[2]?.toLowerCase()}`
    );
    if (
      hashes.some((hash, index) => {
        const algorithm = hash.split(':', 1)[0] ?? '';
        const digest = hash.split(':', 2)[1] ?? '';
        return digest.length !== hashLengths[algorithm] || !hashMatches[index];
      }) ||
      /--hash(?:\s|=)(?!sha(?:256|384|512):)/iu.test(logicalLine)
    ) {
      malformed = true;
      warnings.push(`python-requirements-hash-invalid:${file}`);
      continue;
    }
    const requirement = logicalLine
      .replace(/--hash=(?:sha256|sha384|sha512):[A-Fa-f0-9]+/gu, '')
      .trim();
    const match = requirement.match(
      /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([^\]]+)\])?==([^;\s]+)(?:\s*;\s*(.+))?$/u
    );
    if (!match?.[1] || !match[3] || !exact(match[3])) {
      malformed = true;
      warnings.push(`unresolved-python-requirement:${file}`);
      continue;
    }
    const marker = match[4]?.trim();
    if (marker && marker.length > 1_024) {
      malformed = true;
      warnings.push(`python-requirement-marker-over-budget:${file}`);
      continue;
    }
    const extras = (match[2]?.split(',') ?? [])
      .map((extra) =>
        extra
          .trim()
          .toLowerCase()
          .replace(/[-_.]+/gu, '-')
      )
      .filter((extra) => /^[a-z0-9][a-z0-9._-]{0,127}$/u.test(extra))
      .sort();
    parsedLines.push({
      name: canonicalPythonName(match[1]),
      version: match[3],
      extras: [...new Set(extras)],
      ...(marker ? { marker } : {}),
      hashes: [...new Set(hashes)].sort()
    });
  }
  if (!sourceKnown)
    warnings.push(`python-requirements-source-unverified:${file}`);
  if (parsedLines.some((item) => item.hashes.length === 0))
    warnings.push(`python-requirements-are-declared-pins:${file}`);
  for (const item of parsedLines) {
    const trustedLock = sourceKnown && item.hashes.length > 0;
    const source = !sourceKnown
      ? `${file}:source-unverified:${createHash('sha256').update(logicalLines.join('\n')).digest('hex').slice(0, 16)}`
      : trustedLock
        ? `${file}:pip-compile`
        : `${file}:exact-pin`;
    const context = JSON.stringify({
      ...(item.marker ? { markers: [item.marker] } : {}),
      ...(item.extras.length ? { extras: item.extras } : {}),
      ...(item.hashes.length ? { hashes: item.hashes } : {})
    });
    const hasContext = context !== '{}';
    const variant = hasContext
      ? `:context-${createHash('sha256').update(context).digest('hex').slice(0, 16)}`
      : '';
    packages.push({
      name: item.name,
      version: item.version,
      ecosystem: 'PyPI',
      source,
      resolutionConfidence: !sourceKnown
        ? 'unknown'
        : trustedLock
          ? 'lockfile'
          : 'declared-pin',
      direct: true,
      development: /(?:^|[-_.])(?:dev|test|lint|type|docs?)(?:[-_.]|$)/iu.test(
        file
      ),
      ...(hasContext ? { resolutionContext: context } : {}),
      installPath: `${source}:${item.name}@${item.version}${variant}`
    });
  }
  const lockComplete =
    !malformed &&
    sourceKnown &&
    parsedLines.length === logicalLines.length &&
    parsedLines.every((item) => item.hashes.length > 0);
  return { packages, lockComplete };
}

function pythonRequirementsSourceKnown(text: string): boolean {
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.replace(/\s+#.*$/u, '').trim();
    if (!line || line.startsWith('#')) continue;
    const indexDirective = line.match(
      /^--(?:index-url|extra-index-url)(?:=|\s+)(\S+)/u
    );
    if (indexDirective?.[1]) {
      try {
        const url = new URL(indexDirective[1]);
        if (
          url.protocol !== 'https:' ||
          url.hostname !== 'pypi.org' ||
          !/^\/(?:simple|pypi)(?:\/|$)/u.test(url.pathname) ||
          url.username ||
          url.password ||
          url.search ||
          url.hash ||
          line.startsWith('--extra-index-url')
        )
          return false;
      } catch {
        return false;
      }
      continue;
    }
    if (
      line.startsWith('-') &&
      !line.startsWith('--hash=') &&
      requirementInclude(line) === undefined
    )
      return false;
  }
  return true;
}

type PythonRequirementInput = {
  file: string;
  mode: 'requirements' | 'constraints';
  text: string;
};

function requirementInclude(
  line: string
):
  | { path: string; mode: 'requirements' | 'constraints' }
  | 'invalid'
  | undefined {
  const long = line.match(/^(--requirement|--constraint)(?:\s+|=)(\S+)$/u);
  const shortWithSeparator = line.match(/^(-r|-c)(?:\s+|=)(\S+)$/u);
  const shortAttached = line.match(/^(-r|-c)([^\s].*)$/u);
  const match = long ?? shortWithSeparator ?? shortAttached;
  if (!match) {
    return /^(?:-r|--requirement|-c|--constraint)(?:\s|=|$)/u.test(line)
      ? 'invalid'
      : undefined;
  }
  const directive = match[1];
  const relative = match[2]?.replace(/^(?:"([^"]+)"|'([^']+)')$/u, '$1$2');
  if (!directive || !relative) return 'invalid';
  return {
    path: relative,
    mode:
      directive === '-c' || directive === '--constraint'
        ? 'constraints'
        : 'requirements'
  };
}

async function collectPythonRequirementInputs(
  root: string,
  entry: string,
  fileSource: DependencyFileSource | undefined,
  warnings: string[]
): Promise<PythonRequirementInput[]> {
  const rootIsConstraint = /^constraints(?:-|\.)/iu.test(
    path.posix.basename(entry)
  );
  const pending: Array<{
    file: string;
    mode: 'requirements' | 'constraints';
    depth: number;
  }> = [
    {
      file: entry,
      mode: rootIsConstraint ? 'constraints' : 'requirements',
      depth: 0
    }
  ];
  const seen = new Set<string>();
  const output: PythonRequirementInput[] = [];
  let totalBytes = 0;
  for (let cursor = 0; cursor < pending.length; cursor += 1) {
    const item = pending[cursor];
    if (!item) continue;
    if (item.depth > maximumPythonRequirementDepth) {
      warnings.push('python-requirements-include-depth-budget-exceeded');
      continue;
    }
    const key = `${item.mode}\0${item.file}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (seen.size > maximumPythonRequirementFiles) {
      warnings.push('python-requirements-file-budget-exceeded');
      break;
    }
    let text: string | undefined;
    try {
      text = await readInput(root, item.file, fileSource);
    } catch {
      warnings.push(`python-requirements-include-unavailable:${item.file}`);
      continue;
    }
    if (text === undefined) {
      warnings.push(`python-requirements-include-unavailable:${item.file}`);
      continue;
    }
    totalBytes += Buffer.byteLength(text, 'utf8');
    if (totalBytes > maximumPythonRequirementBytes) {
      warnings.push('python-requirements-byte-budget-exceeded');
      break;
    }
    output.push({ file: item.file, mode: item.mode, text });
    for (const rawLine of text.split(/\r?\n/u)) {
      const line = rawLine.replace(/\s+#.*$/u, '').trim();
      if (!line || line.startsWith('#')) continue;
      const include = requirementInclude(line);
      if (include === undefined) continue;
      if (include === 'invalid') {
        warnings.push(`python-requirements-include-invalid:${item.file}`);
        continue;
      }
      const relative = include.path;
      const normalized = path.posix.normalize(
        path.posix.join(path.posix.dirname(item.file), relative)
      );
      if (
        relative.length > 4_096 ||
        relative.includes('\\') ||
        relative.includes('\0') ||
        /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(relative) ||
        path.posix.isAbsolute(relative) ||
        normalized === '..' ||
        normalized.startsWith('../') ||
        normalized.includes('/../')
      ) {
        warnings.push(`python-requirements-include-outside-root:${item.file}`);
        continue;
      }
      pending.push({
        file: normalized,
        mode: item.mode === 'constraints' ? 'constraints' : include.mode,
        depth: item.depth + 1
      });
    }
  }
  return output.sort(
    (left, right) =>
      left.file.localeCompare(right.file) || left.mode.localeCompare(right.mode)
  );
}

/** Read bounded exact identities and retain failures as explicit incomplete coverage. */
export async function readOtherEcosystemInventoryDetailed(
  root: string,
  fileSource?: DependencyFileSource,
  options: OtherEcosystemInventoryOptions = {}
): Promise<OtherEcosystemInventoryResult> {
  const output: LockedPackage[] = [];
  const warnings: string[] = [];
  let goMvsEdges: DependencyEdge[] = [];
  const loadedLockfiles = new Set<string>();
  let pythonRootRequirements: PythonRootRequirement[] = [];
  let pythonRootManifest: RecordValue | undefined;
  const pythonWorkspaceFiles = new Set<string>();
  const pythonWorkspaceProjects = new Map<string, string>();
  try {
    const pyproject = await readInput(root, 'pyproject.toml', fileSource);
    if (pyproject !== undefined) {
      pythonRootManifest = parseToml(pyproject, {
        unsafeKeyBehaviour: 'throw'
      }) as RecordValue;
      pythonRootRequirements = pythonManifestRequirements(pythonRootManifest);
    }
  } catch {
    warnings.push('invalid-or-unreadable-manifest:pyproject.toml');
  }
  const workspacePatterns = pythonWorkspacePatterns(
    pythonRootManifest,
    warnings
  );
  if (workspacePatterns) {
    const candidatePaths = await pythonWorkspaceManifestPaths(
      root,
      fileSource,
      warnings
    );
    const matchedPatterns = new Set<string>();
    const patternWork = { used: 0, exceeded: false };
    for (const file of candidatePaths) {
      const module = path.posix.dirname(file);
      let member = false;
      for (const pattern of workspacePatterns.members) {
        if (patternWork.exceeded) break;
        if (workspacePatternMatches(pattern, module, patternWork)) {
          matchedPatterns.add(pattern);
          member = true;
          break;
        }
      }
      if (patternWork.exceeded) break;
      if (!member) continue;
      let excluded = false;
      for (const pattern of workspacePatterns.exclude) {
        if (patternWork.exceeded) break;
        if (workspacePatternMatches(pattern, module, patternWork)) {
          excluded = true;
          break;
        }
      }
      if (patternWork.exceeded) break;
      if (excluded) continue;
      let manifest: RecordValue;
      try {
        const text = await readInput(root, file, fileSource);
        if (text === undefined)
          throw new Error('workspace manifest was not captured');
        manifest = parseToml(text, {
          unsafeKeyBehaviour: 'throw'
        }) as RecordValue;
      } catch {
        warnings.push(`python-workspace-manifest-invalid:${module}`);
        continue;
      }
      const name = pythonProjectName(manifest);
      if (!name) {
        warnings.push(`python-workspace-project-name-unavailable:${module}`);
        continue;
      }
      pythonWorkspaceFiles.add(file);
      pythonWorkspaceProjects.set(module, name);
      pythonRootRequirements.push(
        ...pythonManifestRequirements(manifest, module)
      );
    }
    if (patternWork.exceeded)
      warnings.push('python-workspace-pattern-work-budget-exceeded');
    for (const pattern of workspacePatterns.members) {
      if (!matchedPatterns.has(pattern))
        warnings.push(
          `python-workspace-member-pattern-unmatched:${createHash('sha256').update(pattern).digest('hex').slice(0, 16)}`
        );
    }
  }
  const jsonLocks: Array<[string, LockedPackage['ecosystem'], string]> = [
    ['Pipfile.lock', 'PyPI', 'Pipfile.lock'],
    ['composer.lock', 'Packagist', 'composer.lock']
  ];
  for (const [file, ecosystem, source] of jsonLocks) {
    try {
      const text = await readInput(root, file, fileSource);
      if (text === undefined) continue;
      loadedLockfiles.add(file);
      const packages = fromJsonLock(
        JSON.parse(text) as unknown,
        ecosystem,
        source
      );
      output.push(...packages);
      if (packages.length === 0)
        warnings.push(`no-exact-package-records:${file}`);
    } catch {
      warnings.push(`invalid-or-unreadable-lockfile:${file}`);
    }
  }
  const tomlLocks: Array<[string, LockedPackage['ecosystem'], string]> = [
    ['Cargo.lock', 'crates.io', 'Cargo.lock'],
    ['poetry.lock', 'PyPI', 'poetry.lock'],
    ['uv.lock', 'PyPI', 'uv.lock']
  ];
  for (const [file, ecosystem, source] of tomlLocks) {
    try {
      const text = await readInput(root, file, fileSource);
      if (text === undefined) continue;
      loadedLockfiles.add(file);
      const before = output.length;
      output.push(...fromTomlLock(text, ecosystem, source, warnings));
      if (output.length === before)
        warnings.push(`no-exact-package-records:${file}`);
    } catch {
      warnings.push(`invalid-or-unreadable-lockfile:${file}`);
    }
  }
  const composerManifestText = await readInput(
    root,
    'composer.json',
    fileSource
  ).catch(() => {
    warnings.push('invalid-or-unreadable-manifest:composer.json');
    return undefined;
  });
  const composerDirect = new Map<
    string,
    { requirement: string; section: DependencyEdge['section'] }
  >();
  const composerWorkspaceFiles = new Set<string>();
  let composerPathPatterns: string[] = [];
  if (composerManifestText !== undefined) {
    try {
      const manifest = JSON.parse(composerManifestText) as Record<
        string,
        unknown
      >;
      composerPathPatterns = composerPathRepositoryPatterns(manifest, warnings);
      for (const [field, section] of [
        ['require', 'dependency'],
        ['require-dev', 'devDependency']
      ] as const) {
        const entries = manifest[field];
        if (!entries || typeof entries !== 'object' || Array.isArray(entries))
          continue;
        for (const [name, requirement] of Object.entries(entries)) {
          const normalizedName = name.toLowerCase();
          if (
            typeof requirement === 'string' &&
            normalizedName !== 'php' &&
            !normalizedName.startsWith('ext-') &&
            !normalizedName.startsWith('lib-')
          )
            composerDirect.set(normalizedName, { requirement, section });
        }
      }
    } catch {
      warnings.push('invalid-manifest:composer.json');
    }
  }

  const cargoManifestFiles = await cargoManifestPaths(
    root,
    fileSource,
    warnings
  );
  const cargoManifests = new Map<string, RecordValue>();
  for (const file of cargoManifestFiles) {
    try {
      const text = await readInput(root, file, fileSource);
      if (text === undefined) continue;
      const manifest = asRecord(
        parseToml(text, { unsafeKeyBehaviour: 'throw' })
      );
      if (!manifest) throw new Error('cargo-manifest-not-object');
      cargoManifests.set(file, manifest);
    } catch {
      warnings.push(`cargo-manifest-invalid:${file}`);
    }
  }
  const rootCargoManifest = cargoManifests.get('Cargo.toml');
  const cargoWorkspace = asRecord(rootCargoManifest?.workspace);
  const cargoWorkspaceDependencies =
    asRecord(cargoWorkspace?.dependencies) ?? {};
  const cargoMemberPatterns = cargoWorkspacePatterns(
    cargoWorkspace?.members,
    'members',
    warnings
  );
  const cargoExcludedPatterns = cargoWorkspacePatterns(
    cargoWorkspace?.exclude,
    'exclude',
    warnings
  );
  const cargoPatternWork = { used: 0, exceeded: false };
  const cargoWorkspaceVersion = asRecord(cargoWorkspace?.package)?.version;
  const cargoWorkspacePackages: Array<{
    name: string;
    version: string;
    module: string;
    file: string;
    declarations: CargoDependencyDeclaration[];
  }> = [];
  let cargoDeclarationWork = 0;
  let cargoDeclarationWarningAdded = false;
  const cargoWorkspaceLockCandidates = new Map<string, LockedPackage[]>();
  for (const item of output) {
    if (
      item.ecosystem !== 'crates.io' ||
      item.source !== 'Cargo.lock:path-or-workspace-unverified'
    )
      continue;
    const key = JSON.stringify([item.name, item.version.replace(/^v/u, '')]);
    const candidates = cargoWorkspaceLockCandidates.get(key) ?? [];
    candidates.push(item);
    cargoWorkspaceLockCandidates.set(key, candidates);
  }
  for (const [file, manifest] of cargoManifests) {
    const module =
      path.posix.dirname(file) === '.' ? '' : path.posix.dirname(file);
    const packageRecord = asRecord(manifest.package);
    if (!packageRecord) {
      if (file === 'Cargo.toml' && cargoWorkspace) continue;
      if (file !== 'Cargo.toml')
        warnings.push(`cargo-workspace-package-unavailable:${file}`);
      continue;
    }
    const isRoot = file === 'Cargo.toml';
    const included = isRoot
      ? true
      : cargoMemberPatterns.some((pattern) =>
          cargoPatternMatches(pattern, module, cargoPatternWork)
        ) &&
        !cargoExcludedPatterns.some((pattern) =>
          cargoPatternMatches(pattern, module, cargoPatternWork)
        );
    if (cargoPatternWork.exceeded) break;
    if (!included) continue;
    const name =
      typeof packageRecord.name === 'string' ? packageRecord.name : undefined;
    const rawVersion = packageRecord.version;
    const version =
      typeof rawVersion === 'string'
        ? rawVersion
        : asRecord(rawVersion)?.workspace === true &&
            typeof cargoWorkspaceVersion === 'string'
          ? cargoWorkspaceVersion
          : undefined;
    if (!name || !/^[A-Za-z0-9_-]{1,256}$/u.test(name) || !exact(version)) {
      warnings.push(`cargo-workspace-identity-unresolved:${file}`);
      continue;
    }
    const declarations = cargoDependencyDeclarations(
      manifest,
      module,
      cargoWorkspaceDependencies,
      warnings,
      file
    );
    if (
      Object.keys(asRecord(manifest.features) ?? {}).length > 0 ||
      Object.keys(asRecord(manifest.target) ?? {}).length > 0 ||
      declarations.some((declaration) => declaration.requestedFeatures?.length)
    )
      warnings.push(`cargo-active-feature-target-selection-unverified:${file}`);
    const locked =
      cargoWorkspaceLockCandidates.get(
        JSON.stringify([name, version.replace(/^v/u, '')])
      ) ?? [];
    if (locked.length !== 1) {
      warnings.push(`cargo-workspace-package-lock-identity-unresolved:${file}`);
      continue;
    }
    const workspaceItem = locked[0];
    if (!workspaceItem) continue;
    workspaceItem.source = 'Cargo.lock:workspace';
    workspaceItem.resolutionConfidence = 'workspace';
    workspaceItem.module = module || 'root';
    workspaceItem.installPath = `Cargo.lock:workspace:${module || 'root'}:${name}@${version}`;
    workspaceItem.declaredFeatures = Object.keys(
      asRecord(manifest.features) ?? {}
    ).sort();
    const declarationsByName = new Map<string, CargoDependencyDeclaration[]>();
    for (const declaration of declarations) {
      const current = declarationsByName.get(declaration.name) ?? [];
      current.push(declaration);
      declarationsByName.set(declaration.name, current);
    }
    const lockedDependencies = workspaceItem.dependencies ?? [];
    let workspaceDeclarationWork = 0;
    for (const dependency of lockedDependencies) {
      workspaceDeclarationWork +=
        declarationsByName.get(dependency.name)?.length ?? 0;
      if (
        workspaceDeclarationWork + cargoDeclarationWork >
        maximumEcosystemResolutionWork
      )
        break;
    }
    if (
      workspaceDeclarationWork + cargoDeclarationWork >
      maximumEcosystemResolutionWork
    ) {
      if (!cargoDeclarationWarningAdded) {
        warnings.push('cargo-workspace-declaration-work-budget-exceeded');
        cargoDeclarationWarningAdded = true;
      }
    } else {
      cargoDeclarationWork += workspaceDeclarationWork;
      workspaceItem.dependencies = lockedDependencies.flatMap((dependency) => {
        const contexts = (declarationsByName.get(dependency.name) ?? []).filter(
          (context) =>
            cargoRequirementMatches(dependency.requirement, context.requirement)
        );
        if (!contexts?.length) return [dependency];
        return contexts.map((context) => ({
          ...dependency,
          section: context.section,
          ...(context.module !== undefined ? { module: context.module } : {}),
          ...(context.target ? { target: context.target } : {}),
          ...(context.requestedFeatures
            ? { requestedFeatures: context.requestedFeatures }
            : {}),
          ...(context.alias !== context.name ? { alias: context.alias } : {})
        }));
      });
    }
    cargoWorkspacePackages.push({ name, version, module, file, declarations });
  }
  if (cargoPatternWork.exceeded)
    warnings.push('cargo-workspace-pattern-work-budget-exceeded');
  if (
    cargoWorkspace &&
    cargoMemberPatterns.length > 0 &&
    cargoWorkspacePackages.length === 0
  )
    warnings.push('cargo-workspace-graph-incomplete');
  for (const pattern of cargoMemberPatterns) {
    if (
      !cargoManifestFiles.some((file) => {
        const module =
          path.posix.dirname(file) === '.' ? '' : path.posix.dirname(file);
        return (
          Boolean(module) &&
          cargoPatternMatches(pattern, module, cargoPatternWork) &&
          !cargoExcludedPatterns.some((excluded) =>
            cargoPatternMatches(excluded, module, cargoPatternWork)
          )
        );
      })
    )
      warnings.push('cargo-workspace-member-pattern-unmatched');
  }
  if (
    cargoPatternWork.exceeded &&
    !warnings.includes('cargo-workspace-pattern-work-budget-exceeded')
  )
    warnings.push('cargo-workspace-pattern-work-budget-exceeded');
  for (const item of output) {
    if (
      item.ecosystem === 'crates.io' &&
      item.source === 'Cargo.lock:path-or-workspace-unverified'
    ) {
      warnings.push('cargo-path-or-workspace-provenance-unverified');
      warnings.push(`cargo-package-provenance-unknown:${item.name}`);
    }
  }

  if (composerPathPatterns.length > 0) {
    const manifests = await composerManifestPaths(root, fileSource, warnings);
    const lockedComposerNames = new Set(
      output
        .filter((item) => item.ecosystem === 'Packagist')
        .map((item) => item.name)
    );
    for (const file of manifests) {
      if (file === 'composer.json') continue;
      const directory = path.posix.dirname(file);
      if (
        !composerPathPatterns.some((pattern) =>
          composerPathMatches(pattern, directory)
        )
      )
        continue;
      composerWorkspaceFiles.add(file);
      try {
        const text = await readInput(root, file, fileSource);
        if (text === undefined) {
          warnings.push(`composer-workspace-manifest-unavailable:${file}`);
          continue;
        }
        const workspace = composerWorkspacePackage(text, file, warnings);
        if (workspace) {
          if (!lockedComposerNames.has(workspace.name)) {
            output.push(workspace);
            lockedComposerNames.add(workspace.name);
          }
        }
      } catch {
        warnings.push(`composer-workspace-manifest-unavailable:${file}`);
      }
    }
  }

  const requirementPattern =
    /^(?:requirements|constraints)(?:-[^/]+)?\.(?:txt|in)$/u;
  const requirementFiles = (
    fileSource
      ? fileSource.files.filter((file) =>
          requirementPattern.test(path.posix.basename(file))
        )
      : (await readdir(root).catch(() => [])).filter((file) =>
          requirementPattern.test(path.posix.basename(file))
        )
  ).sort();
  if (requirementFiles.length > maximumPythonRequirementFiles)
    warnings.push('python-requirements-file-budget-exceeded');
  const installRequirementFiles = requirementFiles.filter(
    (file) => !/^constraints(?:-|\.)/iu.test(path.posix.basename(file))
  );
  let pipCompileLockAvailable = installRequirementFiles.length > 0;
  const seenPythonRequirementInstances = new Set<string>();
  for (const file of requirementFiles.slice(0, maximumPythonRequirementFiles)) {
    try {
      const inputs = await collectPythonRequirementInputs(
        root,
        file,
        fileSource,
        warnings
      );
      const sourceKnown = inputs.every((input) =>
        pythonRequirementsSourceKnown(input.text)
      );
      for (const input of inputs) {
        const parsed = pipRequirementsPackages(
          input.file,
          input.text,
          warnings,
          sourceKnown
        );
        if (input.mode === 'constraints') {
          warnings.push(
            `python-constraints-not-installed-identities:${input.file}`
          );
          continue;
        }
        for (const item of parsed.packages) {
          const identityKey = [
            item.ecosystem,
            item.source,
            item.installPath,
            item.resolutionContext ?? ''
          ].join('\0');
          if (seenPythonRequirementInstances.has(identityKey)) continue;
          seenPythonRequirementInstances.add(identityKey);
          output.push(item);
        }
        pipCompileLockAvailable &&= parsed.lockComplete;
        if (parsed.packages.length === 0)
          warnings.push(`python-requirements-empty:${input.file}`);
      }
    } catch {
      pipCompileLockAvailable = false;
      warnings.push(`invalid-or-unreadable-lockfile:${file}`);
    }
  }
  if (pipCompileLockAvailable) loadedLockfiles.add('pip-compile-requirements');

  const goWork = await readInput(root, 'go.work', fileSource).catch(() => {
    warnings.push('invalid-or-unreadable-lockfile:go.work');
    return undefined;
  });
  const goWorkspaceReplacements: GoReplacement[] = [];
  const goWorkspaceDirectiveWarnings: string[] = [];
  if (goWork !== undefined && /^\s*replace\b/mu.test(goWork)) {
    // A go.work replacement overrides each member's module replacement.
    parseGoMod(
      goWork,
      'go.work',
      goWorkspaceDirectiveWarnings,
      goWorkspaceReplacements
    );
  }
  const goModulePaths = new Set(['go.mod']);
  if (goWork !== undefined) {
    for (const directory of parseGoWorkspace(goWork)) {
      const normalized = path.posix.normalize(directory.replace(/^"|"$/gu, ''));
      if (
        !directory ||
        directory.includes('\\') ||
        path.posix.isAbsolute(normalized) ||
        normalized === '..' ||
        normalized.startsWith('../')
      ) {
        warnings.push('go-workspace-path-outside-project');
        continue;
      }
      goModulePaths.add(normalized === '.' ? 'go.mod' : `${normalized}/go.mod`);
    }
  }
  const goModules: Array<{ path: string; text: string }> = [];
  for (const modulePath of goModulePaths) {
    try {
      const text = await readInput(root, modulePath, fileSource);
      if (text !== undefined) goModules.push({ path: modulePath, text });
      else if (modulePath !== 'go.mod')
        warnings.push(`go-workspace-module-unavailable:${modulePath}`);
    } catch {
      warnings.push(`invalid-or-unreadable-lockfile:${modulePath}`);
    }
  }
  const goVendorText = await readInput(
    root,
    'vendor/modules.txt',
    fileSource
  ).catch(() => {
    warnings.push('invalid-or-unreadable-lockfile:vendor/modules.txt');
    return undefined;
  });
  let goToolGraphApplied = false;
  if (
    goModules.length > 0 &&
    goVendorText === undefined &&
    options.allowGoToolExecution === true &&
    options.offline !== true
  ) {
    try {
      const captured = await captureGoMvsGraph(root, fileSource, {
        signal: options.signal,
        runner: options.goCommandRunner
      });
      const graph = resolveGoToolGraph(captured);
      output.push(...graph.packages);
      goMvsEdges = graph.edges;
      warnings.push(...graph.warnings);
      goToolGraphApplied = true;
    } catch {
      // Do not expose subprocess stderr: it can include repository metadata.
      warnings.push('go-tool-module-graph-unavailable');
    }
  } else if (
    goModules.length > 0 &&
    goVendorText === undefined &&
    options.allowGoToolExecution === true &&
    options.offline === true
  ) {
    warnings.push('go-tool-execution-disabled-in-offline-mode');
  }
  if (
    goWork !== undefined &&
    goWorkspaceReplacements.length > 0 &&
    !goToolGraphApplied
  )
    warnings.push('go-work-replace-resolution-incomplete');
  if (!goToolGraphApplied) warnings.push(...goWorkspaceDirectiveWarnings);
  if (goVendorText !== undefined) {
    const vendorPackages = fromGoVendorModules(goVendorText, warnings);
    markGoReplacedPackages(
      vendorPackages,
      goWorkspaceReplacements,
      warnings,
      'go.work'
    );
    output.push(...vendorPackages);
    addGoVendorImportGraph(vendorPackages, fileSource, warnings);
    warnings.push('go-vendor-content-integrity-unverified');
  }
  if (goWork === undefined && goModules.length === 0) {
    const goSumOnly = await readInput(root, 'go.sum', fileSource).catch(() => {
      warnings.push('invalid-or-unreadable-lockfile:go.sum');
      return undefined;
    });
    if (goSumOnly !== undefined)
      warnings.push('go.sum-without-go.mod-is-not-an-installed-graph');
  }
  for (const module of goModules) {
    if (goVendorText !== undefined) {
      // Validate the declarations for malformed records, but use the vendor
      // manifest—not go.mod constraints—as the installed graph.
      parseGoMod(module.text, module.path, warnings);
      continue;
    }
    if (goToolGraphApplied) continue;
    const directory = path.posix.dirname(module.path);
    const sumPath = directory === '.' ? 'go.sum' : `${directory}/go.sum`;
    const goSum = await readInput(root, sumPath, fileSource).catch(() => {
      warnings.push(`invalid-or-unreadable-lockfile:${sumPath}`);
      return undefined;
    });
    const checksums =
      goSum === undefined ? new Map() : goSumChecksums(goSum, warnings);
    const replacements: GoReplacement[] = [...goWorkspaceReplacements];
    const goPackages = parseGoMod(
      module.text,
      module.path,
      warnings,
      replacements
    );
    warnings.push(`go-module-graph-not-resolved:${module.path}`);
    for (const item of goPackages) {
      if (item.resolutionConfidence !== 'unknown') {
        item.source = `${module.path}:mvs-unresolved`;
        item.resolutionConfidence = 'unknown';
      }
      const checksum = checksums.get(
        `${item.name}@${item.version.replace(/^v/u, '')}`
      );
      if (checksum) item.integrity = checksum;
      else
        warnings.push(`go-checksum-unavailable:${item.name}@${item.version}`);
    }
    output.push(...goPackages);
    if (goPackages.length === 0)
      warnings.push(`go.mod-has-no-exact-requirements:${module.path}`);
  }

  let gradleLockAvailable = false;
  let gradleLockPackages: LockedPackage[] = [];
  try {
    const gradleText = await readInput(root, 'gradle.lockfile', fileSource);
    if (gradleText !== undefined) {
      gradleLockAvailable = true;
      loadedLockfiles.add('gradle.lockfile');
      gradleLockPackages = fromGradleLock(gradleText);
      if (gradleLockPackages.length === 0)
        warnings.push('no-exact-package-records:gradle.lockfile');
    }
  } catch {
    warnings.push('invalid-or-unreadable-lockfile:gradle.lockfile');
  }
  let mavenTreeAvailable = false;
  let gradleGraphAvailable = false;
  try {
    const gradleExport = await readInput(
      root,
      'gradle-dependencies.json',
      fileSource
    );
    if (gradleExport !== undefined) {
      loadedLockfiles.add('gradle-dependencies.json');
      const graph = fromJavaDependencyGraph(
        JSON.parse(gradleExport) as unknown,
        'Maven',
        'gradle-dependencies.json',
        warnings
      );
      gradleGraphAvailable = true;
      output.push(...graph);
    }
  } catch {
    warnings.push('invalid-or-unreadable-lockfile:gradle-dependencies.json');
  }
  try {
    const mavenExport = await readInput(
      root,
      'maven-dependency-tree.json',
      fileSource
    );
    if (mavenExport !== undefined) {
      loadedLockfiles.add('maven-dependency-tree.json');
      const graph = fromJavaDependencyGraph(
        JSON.parse(mavenExport) as unknown,
        'Maven',
        'maven-dependency-tree.json',
        warnings
      );
      mavenTreeAvailable = true;
      output.push(...graph);
    }
  } catch {
    warnings.push('invalid-or-unreadable-lockfile:maven-dependency-tree.json');
  }
  try {
    const mavenTree = await readInput(
      root,
      'maven-dependency-tree.txt',
      fileSource
    );
    if (mavenTree !== undefined && !mavenTreeAvailable) {
      loadedLockfiles.add('maven-dependency-tree.txt');
      mavenTreeAvailable = true;
      const graph = fromMavenDependencyTree(mavenTree, warnings);
      output.push(...graph);
      if (graph.length === 0)
        warnings.push('no-exact-package-records:maven-dependency-tree.txt');
    }
  } catch {
    warnings.push('invalid-or-unreadable-lockfile:maven-dependency-tree.txt');
  }
  if (!gradleGraphAvailable) output.push(...gradleLockPackages);
  if (gradleLockAvailable && !gradleGraphAvailable)
    warnings.push('gradle-graph-unavailable:gradle.lockfile-has-no-edges');
  const pom = await readInput(root, 'pom.xml', fileSource).catch(() => {
    warnings.push('invalid-or-unreadable-manifest:pom.xml');
    return undefined;
  });
  if (pom !== undefined && !mavenTreeAvailable)
    warnings.push('maven-resolved-graph-unavailable:pom.xml');
  const gradleManifests = fileSource
    ? fileSource.files.filter((file) =>
        /^(?:build|settings)\.gradle(?:\.kts)?$/u.test(file)
      )
    : await readdir(root).catch(() => []);
  if (
    gradleManifests.some((file) =>
      /^(?:build|settings)\.gradle(?:\.kts)?$/u.test(file)
    ) &&
    !gradleGraphAvailable &&
    !gradleLockAvailable
  )
    warnings.push('gradle-resolved-graph-unavailable');
  const projectFiles = fileSource
    ? [...fileSource.files]
    : await readdir(root).catch(() => []);
  const projectFileSet = new Set(projectFiles);
  const hasRoot = (name: string): boolean => projectFileSet.has(name);
  const hasPythonManifest =
    hasRoot('pyproject.toml') ||
    hasRoot('Pipfile') ||
    projectFiles.some((file) =>
      /^(?:requirements|constraints)(?:-[^/]+)?\.(?:txt|in)$/u.test(
        path.posix.basename(file)
      )
    );
  if (
    hasPythonManifest &&
    ![
      'Pipfile.lock',
      'poetry.lock',
      'uv.lock',
      'pip-compile-requirements'
    ].some((file) => loadedLockfiles.has(file))
  )
    warnings.push('python-resolved-lock-graph-unavailable');
  if (hasRoot('Cargo.toml') && !loadedLockfiles.has('Cargo.lock'))
    warnings.push('cargo-lockfile-unavailable');
  if (
    composerManifestText !== undefined &&
    !loadedLockfiles.has('composer.lock')
  )
    warnings.push('composer-lockfile-unavailable');
  if (
    (hasRoot('pom.xml') ||
      projectFiles.some((file) =>
        /^pom\.xml$/u.test(path.posix.basename(file))
      )) &&
    !mavenTreeAvailable
  )
    warnings.push('maven-resolved-graph-unavailable');
  const cargoWorkspaceFiles = new Set(
    cargoWorkspacePackages.map((member) => member.file)
  );
  for (const file of projectFiles) {
    const basename = path.posix.basename(file);
    const nested = file.includes('/');
    if (!nested) continue;
    if (basename === 'pyproject.toml' && pythonWorkspaceFiles.has(file))
      continue;
    if (basename === 'composer.json' && composerWorkspaceFiles.has(file))
      continue;
    if (basename === 'Cargo.toml' && cargoWorkspaceFiles.has(file)) continue;
    if (
      /^(?:Cargo\.toml|composer\.json|pom\.xml|pyproject\.toml|Pipfile|(?:requirements|constraints)(?:-[^/]+)?\.(?:txt|in)|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?)$/u.test(
        basename
      )
    )
      warnings.push('ecosystem-workspace-graph-incomplete');
  }
  const unique = new Map<string, DependencyIdentity>();
  for (const item of output) {
    if (item.source === 'composer.lock:path-unverified')
      warnings.push(`composer-path-source-unverified:${item.name}`);
    if (
      item.ecosystem === 'Packagist' &&
      item.source === 'composer.lock' &&
      item.resolutionConfidence === 'unknown'
    )
      warnings.push(`composer-branch-version-unverified:${item.name}`);
    const dependency = identity(item);
    unique.set(dependency.id, dependency);
  }
  const packages = [...unique.values()].sort((a, b) =>
    a.id.localeCompare(b.id)
  );
  const byName = new Map<string, DependencyIdentity[]>();
  for (const dependency of packages) {
    const key = `${dependency.ecosystem}\0${dependency.name}`;
    const values = byName.get(key) ?? [];
    values.push(dependency);
    byName.set(key, values);
  }
  const contextByDependency = new WeakMap<
    DependencyIdentity,
    { markers?: Set<string>; extras: Set<string> }
  >();
  const resolutionByName = new Map<
    string,
    {
      candidates: DependencyIdentity[];
      hasMarkerContexts: boolean;
      byMarker: Map<string, DependencyIdentity[]>;
    }
  >();
  for (const [key, candidates] of byName) {
    const index = {
      candidates,
      hasMarkerContexts: false,
      byMarker: new Map<string, DependencyIdentity[]>()
    };
    for (const candidate of candidates) {
      let context: { markers?: Set<string>; extras: Set<string> } = {
        extras: new Set()
      };
      try {
        const parsed = JSON.parse(candidate.resolutionContext ?? '{}') as {
          markers?: unknown;
          extras?: unknown;
        };
        const markers = Array.isArray(parsed.markers)
          ? parsed.markers.filter(
              (value): value is string => typeof value === 'string'
            )
          : typeof parsed.markers === 'string'
            ? [parsed.markers]
            : undefined;
        const extras = Array.isArray(parsed.extras)
          ? parsed.extras.filter(
              (value): value is string => typeof value === 'string'
            )
          : [];
        context = {
          ...(markers ? { markers: new Set(markers) } : {}),
          extras: new Set(extras)
        };
      } catch {
        // Malformed contexts remain unavailable for targeted resolution.
      }
      contextByDependency.set(candidate, context);
      if (context.markers) {
        index.hasMarkerContexts = true;
        for (const marker of context.markers) {
          const matches = index.byMarker.get(marker) ?? [];
          matches.push(candidate);
          index.byMarker.set(marker, matches);
        }
      }
    }
    resolutionByName.set(key, index);
  }
  const pythonPackagesByWorkspaceName = new Map<string, DependencyIdentity[]>();
  for (const item of packages) {
    if (
      item.ecosystem !== 'PyPI' ||
      !item.workspace ||
      item.resolutionConfidence !== 'workspace'
    )
      continue;
    const key = JSON.stringify([item.workspace, item.name]);
    const matches = pythonPackagesByWorkspaceName.get(key) ?? [];
    matches.push(item);
    pythonPackagesByWorkspaceName.set(key, matches);
  }
  const pythonWorkspacePackages = new Map<string, DependencyIdentity>();
  for (const [module, name] of pythonWorkspaceProjects) {
    const matches =
      pythonPackagesByWorkspaceName.get(JSON.stringify([module, name])) ?? [];
    if (matches.length !== 1) {
      warnings.push(`python-workspace-package-unresolved:${module}`);
      continue;
    }
    const workspacePackage = matches[0];
    if (workspacePackage) pythonWorkspacePackages.set(module, workspacePackage);
  }
  const edges: DependencyEdge[] = [...goMvsEdges];
  let ecosystemResolutionWork = 0;
  let ecosystemResolutionWorkExceeded = false;
  const filterCandidates = <T>(
    candidates: readonly T[],
    predicate: (candidate: T) => boolean
  ): T[] => {
    const matches: T[] = [];
    for (const candidate of candidates) {
      if (ecosystemResolutionWork >= maximumEcosystemResolutionWork) {
        ecosystemResolutionWorkExceeded = true;
        break;
      }
      ecosystemResolutionWork += 1;
      if (predicate(candidate)) matches.push(candidate);
    }
    return matches;
  };
  const resolveTarget = (
    ecosystem: DependencyIdentity['ecosystem'],
    name: string,
    requirement: string,
    module?: string,
    marker?: string,
    extras?: readonly string[]
  ): DependencyIdentity | undefined => {
    const index = resolutionByName.get(`${ecosystem}\0${name}`);
    const candidates = index?.candidates ?? [];
    if (ecosystem === 'Packagist') {
      const matches = filterCandidates(candidates, (candidate) =>
        composerRequirementMatches(candidate.version, requirement)
      );
      if (ecosystemResolutionWorkExceeded) return undefined;
      return matches.length === 1 ? matches[0] : undefined;
    }
    let markerCandidates: DependencyIdentity[] = [];
    if (marker) {
      markerCandidates = index?.byMarker.get(marker) ?? [];
      if (index?.hasMarkerContexts && markerCandidates.length === 0)
        return undefined;
    }
    let resolutionCandidates =
      markerCandidates.length > 0 ? markerCandidates : candidates;
    if (extras?.length) {
      const withExtraContexts = filterCandidates(
        resolutionCandidates,
        (candidate) => {
          const contextExtras = contextByDependency.get(candidate)?.extras;
          return (
            Boolean(contextExtras?.size) &&
            extras.every((extra) => contextExtras?.has(extra))
          );
        }
      );
      if (ecosystemResolutionWorkExceeded) return undefined;
      if (withExtraContexts.length > 0)
        resolutionCandidates = withExtraContexts;
    }
    if (ecosystem === 'crates.io') {
      const cargoMatches = filterCandidates(resolutionCandidates, (candidate) =>
        cargoRequirementMatches(candidate.version, requirement)
      );
      if (ecosystemResolutionWorkExceeded) return undefined;
      const moduleMatches = module
        ? filterCandidates(
            cargoMatches,
            (candidate) => candidate.workspace === module
          )
        : [];
      if (ecosystemResolutionWorkExceeded) return undefined;
      const matches = moduleMatches.length > 0 ? moduleMatches : cargoMatches;
      return matches.length === 1 ? matches[0] : undefined;
    }
    if (ecosystem === 'PyPI') {
      const matches = filterCandidates(resolutionCandidates, (candidate) =>
        pythonRequirementMatches(candidate.version, requirement)
      );
      if (ecosystemResolutionWorkExceeded) return undefined;
      return matches.length === 1 ? matches[0] : undefined;
    }
    const exactVersion = requirement
      .replace(/^(?:===|==)/u, '')
      .replace(/^v/u, '');
    const allExact = filterCandidates(
      resolutionCandidates,
      (candidate) => candidate.version.replace(/^v/u, '') === exactVersion
    );
    if (ecosystemResolutionWorkExceeded) return undefined;
    const moduleExact = module
      ? filterCandidates(
          allExact,
          (candidate) => candidate.workspace === module
        )
      : [];
    if (ecosystemResolutionWorkExceeded) return undefined;
    const exact = moduleExact.length > 0 ? moduleExact : allExact;
    if (exact.length === 1) return exact[0];
    if (exact.length > 1) return undefined;
    return resolutionCandidates.length === 1
      ? resolutionCandidates[0]
      : undefined;
  };
  resolution: for (const item of output) {
    const parent = identity(item);
    for (const dependency of item.dependencies ?? []) {
      const target = resolveTarget(
        item.ecosystem,
        dependency.name,
        dependency.requirement,
        dependency.module,
        dependency.marker,
        dependency.extras
      );
      if (!target) {
        if (ecosystemResolutionWorkExceeded) {
          warnings.push('ecosystem-resolution-work-budget-exceeded');
          break resolution;
        }
        warnings.push(
          `unresolved-${item.ecosystem}-dependency:${dependency.name}:${item.name}`
        );
        continue;
      }
      edges.push({
        from: parent.id,
        to: target.id,
        name: dependency.name,
        requirement: dependency.requirement,
        section: dependency.section,
        ...(dependency.marker ? { marker: dependency.marker } : {}),
        ...(dependency.extras ? { extras: dependency.extras } : {}),
        ...(dependency.requestedFeatures
          ? { requestedFeatures: dependency.requestedFeatures }
          : {}),
        ...(dependency.alias ? { alias: dependency.alias } : {}),
        ...(dependency.target ? { target: dependency.target } : {})
      });
    }
  }
  for (const member of cargoWorkspacePackages) {
    const workspaceIdentity = resolveTarget(
      'crates.io',
      member.name,
      member.version,
      member.module || 'root'
    );
    if (!workspaceIdentity) {
      warnings.push(`cargo-workspace-member-unresolved:${member.file}`);
      continue;
    }
    if (member.module) {
      edges.push({
        from: 'root',
        to: workspaceIdentity.id,
        name: member.name,
        requirement: member.version,
        section: 'dependency'
      });
    }
    for (const declaration of member.declarations) {
      const target = resolveTarget(
        'crates.io',
        declaration.name,
        declaration.requirement,
        declaration.module,
        declaration.target
      );
      if (!target) {
        warnings.push(
          `unresolved-crates.io-root-dependency:${member.module || 'root'}:${declaration.name}`
        );
        continue;
      }
      target.direct = true;
      if (declaration.section === 'devDependency') target.development = true;
      edges.push({
        from: 'root',
        to: target.id,
        name: declaration.name,
        ...(declaration.alias !== declaration.name
          ? { alias: declaration.alias }
          : {}),
        requirement: declaration.requirement,
        section: declaration.section,
        ...(declaration.target ? { target: declaration.target } : {}),
        ...(declaration.requestedFeatures?.length
          ? { requestedFeatures: declaration.requestedFeatures }
          : {})
      });
    }
  }
  for (const dependency of packages.filter(
    (item) =>
      item.ecosystem === 'Maven' &&
      (item.source === 'maven-dependency-tree.txt' ||
        item.source === 'maven-dependency-tree.json' ||
        item.source === 'gradle-dependencies.json') &&
      item.direct
  ))
    edges.push({
      from: 'root',
      to: dependency.id,
      name: dependency.name,
      requirement: dependency.version,
      section: dependency.optional
        ? 'optionalDependency'
        : dependency.development
          ? 'devDependency'
          : 'dependency'
    });
  for (const [name, spec] of composerDirect) {
    const target = resolveTarget('Packagist', name, spec.requirement);
    if (!target) {
      warnings.push(`unresolved-Packagist-root-dependency:${name}`);
      continue;
    }
    target.direct = true;
    target.development = spec.section === 'devDependency';
    edges.push({
      from: 'root',
      to: target.id,
      name,
      requirement: spec.requirement,
      section: spec.section
    });
  }
  for (const dependency of packages.filter(
    (item) =>
      item.ecosystem === 'PyPI' && item.resolutionConfidence === 'declared-pin'
  ))
    edges.push({
      from: 'root',
      to: dependency.id,
      name: dependency.name,
      requirement: `==${dependency.version}`,
      section: dependency.development ? 'devDependency' : 'dependency'
    });
  for (const dependency of packages.filter(
    (item) =>
      item.ecosystem === 'PyPI' &&
      /^(?:requirements|constraints)(?:-[^/]+)?\.(?:txt|in):(?:pip-compile|exact-pin|source-unverified)(?::[a-f0-9]{16})?$/u.test(
        item.source
      )
  )) {
    let context: { markers?: unknown; extras?: unknown } = {};
    try {
      context = JSON.parse(
        dependency.resolutionContext ?? '{}'
      ) as typeof context;
    } catch {
      warnings.push(`python-requirement-context-invalid:${dependency.name}`);
    }
    const marker =
      typeof context.markers === 'string'
        ? context.markers
        : Array.isArray(context.markers) &&
            typeof context.markers[0] === 'string'
          ? context.markers[0]
          : undefined;
    const extras = Array.isArray(context.extras)
      ? context.extras.filter(
          (extra): extra is string => typeof extra === 'string'
        )
      : undefined;
    edges.push({
      from: 'root',
      to: dependency.id,
      name: dependency.name,
      requirement: `==${dependency.version}`,
      section: dependency.development ? 'devDependency' : 'dependency',
      ...(marker ? { marker } : {}),
      ...(extras?.length ? { extras } : {})
    });
  }
  for (const requirement of pythonRootRequirements) {
    const target = resolveTarget(
      'PyPI',
      requirement.name,
      requirement.requirement,
      undefined,
      requirement.marker,
      requirement.extras
    );
    if (!target) {
      warnings.push(`unresolved-PyPI-root-dependency:${requirement.name}`);
      continue;
    }
    const workspacePackage = requirement.module
      ? pythonWorkspacePackages.get(requirement.module)
      : undefined;
    if (requirement.module && !workspacePackage) continue;
    target.direct = true;
    if (requirement.section === 'devDependency') target.development = true;
    edges.push({
      from: workspacePackage?.id ?? 'root',
      to: target.id,
      name: requirement.name,
      requirement: requirement.requirement,
      section: requirement.section,
      ...(requirement.module ? { module: requirement.module } : {}),
      ...(requirement.marker ? { marker: requirement.marker } : {}),
      ...(requirement.extras ? { extras: requirement.extras } : {})
    });
  }
  for (const dependency of packages.filter(
    (item) => item.ecosystem === 'Go' && item.direct
  ))
    edges.push({
      from: 'root',
      to: dependency.id,
      name: dependency.name,
      requirement: dependency.version,
      section: 'dependency'
    });
  if (
    output.some((item) => item.source === 'gradle.lockfile') &&
    !mavenTreeAvailable
  )
    warnings.push('maven-graph-unavailable:gradle.lockfile-has-no-edges');
  return {
    packages,
    edges: [
      ...new Map(
        edges.map((edge) => [
          `${edge.from}\0${edge.to}\0${edge.section}\0${edge.marker ?? ''}\0${(edge.extras ?? []).join(',')}`,
          edge
        ])
      ).values()
    ].sort((a, b) => `${a.from}:${a.to}`.localeCompare(`${b.from}:${b.to}`)),
    warnings: [...new Set(warnings)].sort(),
    complete: warnings.length === 0
  };
}

function canonicalPythonName(value: string): string {
  return value.toLowerCase().replace(/[-_.]+/gu, '-');
}

function composerPathRepositoryPatterns(
  manifest: RecordValue,
  warnings: string[]
): string[] {
  if (manifest.repositories === undefined) return [];
  if (!Array.isArray(manifest.repositories)) {
    warnings.push('composer-path-repositories-invalid');
    return [];
  }
  const patterns: string[] = [];
  for (const repository of manifest.repositories) {
    const entry = asRecord(repository);
    if (entry?.type !== 'path') continue;
    if (typeof entry.url !== 'string' || entry.url.length > 512) {
      warnings.push('composer-path-repository-url-invalid');
      continue;
    }
    const url = entry.url.replaceAll('\\', '/');
    const normalized = path.posix.normalize(url.replace(/^\.\//u, ''));
    if (
      !normalized ||
      path.posix.isAbsolute(url) ||
      normalized === '..' ||
      normalized.startsWith('../') ||
      normalized.includes('\0') ||
      ['?', '[', ']', '{', '}'].some((character) =>
        normalized.includes(character)
      )
    ) {
      warnings.push('composer-path-repository-outside-or-unsupported');
      continue;
    }
    patterns.push(normalized);
  }
  const unique = [...new Set(patterns)].sort();
  if (unique.length > maximumComposerPathRepositories)
    warnings.push('composer-path-repository-budget-exceeded');
  return unique.slice(0, maximumComposerPathRepositories);
}

function composerPathMatches(pattern: string, directory: string): boolean {
  let expression = '^';
  for (let index = 0; index < pattern.length; index++) {
    const character = pattern[index] ?? '';
    if (character === '*' && pattern[index + 1] === '*') {
      expression += '.*';
      index++;
    } else if (character === '*') {
      expression += '[^/]*';
    } else {
      expression += character.replace(/[|\\{}()[\]^$+?.]/gu, '\\$&');
    }
  }
  expression += '$';
  return new RegExp(expression, 'u').test(directory);
}

async function composerManifestPaths(
  root: string,
  fileSource: DependencyFileSource | undefined,
  warnings: string[]
): Promise<string[]> {
  if (fileSource) {
    const paths = fileSource.files
      .filter((file) => path.posix.basename(file) === 'composer.json')
      .sort();
    if (paths.length > maximumComposerWorkspaceManifests)
      warnings.push('composer-workspace-manifest-budget-exceeded');
    return paths.slice(0, maximumComposerWorkspaceManifests);
  }
  const paths: string[] = [];
  const pending: Array<{ directory: string; depth: number }> = [
    { directory: '', depth: 0 }
  ];
  let entries = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) continue;
    if (current.depth > 32) {
      warnings.push('composer-workspace-depth-budget-exceeded');
      continue;
    }
    let children: Dirent[];
    try {
      children = await readdir(path.join(root, current.directory), {
        withFileTypes: true
      });
    } catch {
      warnings.push('composer-workspace-directory-unavailable');
      continue;
    }
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      if (++entries > maximumComposerWorkspaceEntries) {
        warnings.push('composer-workspace-entry-budget-exceeded');
        return paths.sort();
      }
      const relative = current.directory
        ? `${current.directory}/${child.name}`
        : child.name;
      if (
        child.isDirectory() &&
        !child.isSymbolicLink() &&
        !['.git', 'node_modules', 'vendor', 'dist', 'build'].includes(
          child.name
        )
      ) {
        pending.push({ directory: relative, depth: current.depth + 1 });
      } else if (child.isFile() && child.name === 'composer.json') {
        paths.push(relative);
        if (paths.length >= maximumComposerWorkspaceManifests) {
          warnings.push('composer-workspace-manifest-budget-exceeded');
          return paths.sort();
        }
      }
    }
  }
  return paths.sort();
}

function composerWorkspacePackage(
  manifestText: string,
  file: string,
  warnings: string[]
): LockedPackage | undefined {
  let manifest: RecordValue | undefined;
  try {
    manifest = asRecord(JSON.parse(manifestText));
  } catch {
    warnings.push(`composer-workspace-manifest-invalid:${file}`);
    return undefined;
  }
  if (
    !manifest ||
    typeof manifest.name !== 'string' ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(manifest.name) ||
    typeof manifest.version !== 'string' ||
    !exact(manifest.version)
  ) {
    warnings.push(`composer-workspace-identity-unresolved:${file}`);
    return undefined;
  }
  const module = path.posix.dirname(file);
  const dependencies: NonNullable<LockedPackage['dependencies']> = [];
  for (const [field, section] of [
    ['require', 'dependency'],
    ['require-dev', 'devDependency']
  ] as const) {
    const requirements = asRecord(manifest[field]);
    for (const [name, requirement] of Object.entries(requirements ?? {})) {
      const normalizedName = name.toLowerCase();
      if (
        typeof requirement !== 'string' ||
        normalizedName === 'php' ||
        normalizedName.startsWith('ext-') ||
        normalizedName.startsWith('lib-')
      )
        continue;
      dependencies.push({
        name: normalizedName,
        requirement,
        section
      });
    }
  }
  const name = manifest.name.toLowerCase();
  const version = manifest.version.replace(/^v/u, '');
  const isStableVersion = semver.valid(version) !== null;
  if (!isStableVersion)
    warnings.push(`composer-workspace-version-unverified:${file}`);
  return {
    name,
    version,
    ecosystem: 'Packagist',
    source: 'composer.json:path-repository',
    resolutionConfidence: isStableVersion ? 'workspace' : 'unknown',
    module,
    installPath: `composer-path:${module}:${name}@${version}`,
    dependencies
  };
}

function composerRequirementMatches(
  version: string,
  requirement: string
): boolean {
  const clean = requirement.trim().replace(/@[A-Za-z]+$/u, '');
  if (!clean || clean === '*') return true;
  if (version === clean || version === clean.replace(/^v/u, '')) return true;
  const normalizedVersion = version.replace(/^v/u, '');
  const normalizedRange = clean.replaceAll(',', ' ');
  if (!semver.valid(normalizedVersion) || !semver.validRange(normalizedRange))
    return false;
  return semver.satisfies(normalizedVersion, normalizedRange, {
    includePrerelease: true
  });
}

export async function readOtherEcosystemInventory(
  root: string,
  fileSource?: DependencyFileSource,
  options: OtherEcosystemInventoryOptions = {}
): Promise<DependencyIdentity[]> {
  return (await readOtherEcosystemInventoryDetailed(root, fileSource, options))
    .packages;
}
