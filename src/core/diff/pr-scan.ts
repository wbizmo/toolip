import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { analyzeAstSource } from '../../analyzers/ast/source-analysis.js';
import type { Finding, FindingSeverity } from '../../contracts/finding.js';
import { resolveCommit } from '../git/revision.js';
import { runGitChecked } from '../git/safe-git.js';
import {
  readNpmDependencyGraph,
  type DependencyFileSource,
  type DependencyIdentity
} from '../dependencies/inventory.js';
import { readOtherEcosystemInventoryDetailed } from '../dependencies/ecosystem-inventory.js';
import { OsvClient } from '../../providers/osv/client.js';
import type { OsvVulnerability } from '../../providers/osv/types.js';
import {
  scanConfigurationContent,
  scanSecretContent
} from '../security-doctor.js';

const zeroOid = /^0+$/u;
const maxChangedFiles = 2_000;
const maxFileBytes = 2 * 1024 * 1024;
const maxTotalBytes = 64 * 1024 * 1024;
const maxDependencyInputs = 512;
const maxDependencyTreeEntries = 100_000;
const maxPrAdvisoryQueries = 2_000;
const maxDependencyImpactItems = 500;
const maxPrAdvisoryResponseBytes = 8 * 1024 * 1024;
const maxInlineReviewComments = 500;
const sourceExtensions = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);
const dependencyGraphInput =
  /(?:^|\/)(?:package\.json|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|yarn\.lock|\.npmrc|\.yarnrc(?:\.yml)?|Cargo\.(?:toml|lock)|go\.(?:mod|sum|work|work\.sum)|vendor\/modules\.txt|pyproject\.toml|Pipfile(?:\.lock)?|poetry\.lock|uv\.lock|pdm\.lock|requirements(?:-[^/]+)?\.(?:txt|in)|constraints(?:-[^/]+)?\.(?:txt|in)|setup\.(?:py|cfg)|composer\.(?:json|lock)|pom\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?|gradle\.lockfile|libs\.versions\.toml)$/iu;
const executionEntrypointPath =
  /(?:^|\/)(?:package\.json|\.vscode\/tasks\.json|\.husky\/[^/]+|\.github\/workflows\/[^/]+\.ya?ml|(?:eslint(?:\.config)?|\.eslintrc|vite\.config|webpack\.config|rollup\.config)(?:\.[^/]*)?)$/iu;
const infrastructurePath =
  /(?:^|\/)(?:Dockerfile(?:\.[^/]*)?|docker-compose(?:\.[^/]*)?\.ya?ml|[^/]+\.(?:tf|hcl))$/iu;
const infrastructureWorkflowPath = /^\.github\/workflows\/[^/]+\.ya?ml$/iu;
const policyPath =
  /(?:^|\/)(?:\.toolip\/)?(?:organization-)?(?:toolip-)?policy\.(?:json|ya?ml)$/iu;

export type PrFileChange = Readonly<{
  status: string;
  oldPath: string;
  newPath: string;
  oldOid?: string;
  newOid?: string;
  oldMode: string;
  newMode: string;
}>;

export type ChangedLineRange = Readonly<{
  start: number;
  end: number;
}>;

export type SafeInlineReviewComment = Readonly<{
  path: string;
  line: number;
  ruleId: string;
  severity: FindingSeverity;
  body: string;
}>;

export type PrScanResult = Readonly<{
  base: string;
  head: string;
  baseCommit: string;
  headCommit: string;
  changedFiles: readonly PrFileChange[];
  changedLineRanges: Readonly<Record<string, readonly ChangedLineRange[]>>;
  introduced: readonly Finding[];
  inlineReviewComments: readonly SafeInlineReviewComment[];
  inlineReviewCommentsTruncated: boolean;
  fixed: readonly Finding[];
  unchangedCount: number;
  dependencyImpact?: DependencyGraphImpact;
  coverage: 'diff-only' | 'incomplete';
  analysisState: 'partial' | 'failed';
  reasons: readonly string[];
}>;

export type DependencyGraphImpact = Readonly<{
  state: 'complete' | 'incomplete';
  basePackageCount: number;
  headPackageCount: number;
  addedCount: number;
  removedCount: number;
  versionChangedCount: number;
  added: readonly DependencyGraphImpactItem[];
  removed: readonly DependencyGraphImpactItem[];
  versionChanged: readonly {
    before: DependencyGraphImpactItem;
    after: DependencyGraphImpactItem;
  }[];
  truncated: boolean;
  warnings: readonly string[];
  advisoryStatus: 'not-recomputed' | 'complete' | 'incomplete';
  introducedAdvisories: readonly DependencyAdvisoryImpact[];
  fixedAdvisories: readonly DependencyAdvisoryImpact[];
}>;

export type DependencyAdvisoryImpact = Readonly<{
  ecosystem: DependencyIdentity['ecosystem'];
  name: string;
  version: string;
  installPath: string;
  advisoryId: string;
  aliases: readonly string[];
}>;

export type PrScanOptions = {
  /** Query OSV only when the caller explicitly opts into external requests. */
  onlineAdvisories?: boolean;
  /** Consent to send public npm scoped names to OSV. */
  allowPublicScope?: boolean;
  /** Injectable provider for deterministic tests and approved deployments. */
  advisoryClient?: Pick<OsvClient, 'queryBatch'>;
};

export type DependencyGraphImpactItem = Readonly<{
  ecosystem: DependencyIdentity['ecosystem'];
  name: string;
  version: string;
  direct: boolean;
  installPath: string;
  resolutionConfidence: DependencyIdentity['resolutionConfidence'];
}>;

/** Parses NUL-delimited `git diff --raw` without interpreting paths as options. */
export function parseRawChanges(output: Buffer): PrFileChange[] {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(output);
  } catch {
    throw new Error('Git change paths contain invalid UTF-8.');
  }
  const fields = text.split('\0');
  if (fields.at(-1) !== '') throw new Error('Git change list is truncated.');
  const changes: PrFileChange[] = [];
  for (let index = 0; index < fields.length - 1;) {
    const header = fields[index++];
    const match = header?.match(
      /^:([0-7]{6}) ([0-7]{6}) ([a-f0-9]{40,64}) ([a-f0-9]{40,64}) ([A-Z][0-9]*)$/u
    );
    if (!match?.[1] || !match[2] || !match[3] || !match[4] || !match[5])
      throw new Error('Git change metadata is malformed.');
    const firstPath = fields[index++];
    if (!firstPath) throw new Error('Git change path is missing.');
    const status = match[5];
    const renamed = status.startsWith('R') || status.startsWith('C');
    const secondPath = renamed ? fields[index++] : firstPath;
    if (!secondPath) throw new Error('Git rename target is missing.');
    const oldOid = zeroOid.test(match[3]) ? undefined : match[3];
    const newOid = zeroOid.test(match[4]) ? undefined : match[4];
    changes.push(
      Object.freeze({
        status,
        oldPath: firstPath,
        newPath: secondPath,
        ...(oldOid ? { oldOid } : {}),
        ...(newOid ? { newOid } : {}),
        oldMode: match[1],
        newMode: match[2]
      })
    );
    if (changes.length > maxChangedFiles)
      throw new Error('Git change list exceeds the file-count budget.');
  }
  return changes;
}

export function parseChangedLineRanges(
  output: Buffer
): Readonly<Record<string, readonly ChangedLineRange[]>> {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(output);
  } catch {
    throw new Error('Git diff contains invalid UTF-8.');
  }
  const ranges = new Map<string, ChangedLineRange[]>();
  let currentPath: string | undefined;
  for (const line of text.split(/\r?\n/u)) {
    if (line.startsWith('+++ ')) {
      const value = line.slice(4);
      if (value.startsWith('"'))
        throw new Error(
          'Quoted Git paths cannot be mapped to changed lines safely.'
        );
      currentPath =
        value === '/dev/null' ? undefined : value.replace(/^b\//u, '');
      continue;
    }
    if (!currentPath || !line.startsWith('@@ ')) continue;
    const hunk = line.match(/\+([0-9]+)(?:,([0-9]+))?/u);
    if (!hunk?.[1]) continue;
    const start = Number(hunk[1]);
    const count = Number(hunk[2] ?? '1');
    if (
      !Number.isSafeInteger(start) ||
      !Number.isSafeInteger(count) ||
      count < 1
    )
      continue;
    const current = ranges.get(currentPath) ?? [];
    current.push(Object.freeze({ start, end: start + count - 1 }));
    ranges.set(currentPath, current);
  }
  return Object.freeze(
    Object.fromEntries(
      [...ranges].map(([file, fileRanges]) => [file, Object.freeze(fileRanges)])
    )
  );
}

function parseBatchBlobs(
  output: Buffer,
  oids: readonly string[]
): Map<string, Buffer> {
  const blobs = new Map<string, Buffer>();
  let offset = 0;
  for (const oid of oids) {
    const newline = output.indexOf(10, offset);
    if (newline < 0) throw new Error('Git blob response header is truncated.');
    const header = output.subarray(offset, newline).toString('ascii');
    const match = header.match(/^([a-f0-9]{40,64}) blob ([0-9]+)$/u);
    if (!match || match[1] !== oid)
      throw new Error('Git blob response does not match the requested object.');
    const bytes = Number(match[2]);
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxFileBytes)
      throw new Error('Changed Git blob exceeds the per-file byte budget.');
    const start = newline + 1;
    const end = start + bytes;
    if (end >= output.length || output[end] !== 10)
      throw new Error('Git blob response is truncated.');
    blobs.set(oid, output.subarray(start, end));
    offset = end + 1;
  }
  if (offset !== output.length)
    throw new Error('Git returned unexpected trailing blob data.');
  return blobs;
}

async function loadBlobs(
  root: string,
  oids: readonly string[],
  signal?: AbortSignal
): Promise<Map<string, Buffer>> {
  const unique = [...new Set(oids)];
  if (unique.length === 0) return new Map();
  const output = await runGitChecked(
    ['--no-replace-objects', 'cat-file', '--batch'],
    {
      cwd: root,
      signal,
      timeoutMs: 30_000,
      maxBuffer: maxTotalBytes + unique.length * 128,
      input: `${unique.join('\n')}\n`
    }
  );
  return parseBatchBlobs(output, unique);
}

type DependencyTreeEntry = {
  oid: string;
  mode: string;
  type: string;
  path: string;
};

function parseDependencyTree(output: Buffer): {
  entries: DependencyTreeEntry[];
  warnings: string[];
} {
  const warnings: string[] = [];
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(output);
  } catch {
    return { entries: [], warnings: ['dependency-tree-paths-invalid-utf8'] };
  }
  if (text !== '' && !text.endsWith('\0'))
    return { entries: [], warnings: ['dependency-tree-list-truncated'] };
  const entries: DependencyTreeEntry[] = [];
  const fields = text.split('\0');
  let treeEntriesSeen = 0;
  for (const field of fields) {
    if (!field) continue;
    if (++treeEntriesSeen > maxDependencyTreeEntries) {
      warnings.push('dependency-tree-entry-budget-exceeded');
      break;
    }
    const separator = field.indexOf('\t');
    if (separator < 0) {
      warnings.push('dependency-tree-entry-malformed');
      continue;
    }
    const metadata = field.slice(0, separator).split(' ');
    const relativePath = field.slice(separator + 1);
    const [mode, type, oid] = metadata;
    if (
      !mode ||
      !type ||
      !oid ||
      !/^[0-7]{6}$/u.test(mode) ||
      !/^(?:blob|commit)$/u.test(type) ||
      !/^[a-f0-9]{40,64}$/iu.test(oid)
    ) {
      warnings.push('dependency-tree-entry-malformed');
      continue;
    }
    if (!dependencyGraphInput.test(relativePath)) continue;
    if (
      relativePath.includes('\\') ||
      relativePath.includes('\0') ||
      relativePath.startsWith('/') ||
      relativePath.split('/').some((part) => part === '..') ||
      hasControlCharacter(relativePath)
    ) {
      warnings.push('dependency-tree-input-path-invalid');
      continue;
    }
    if (mode === '120000' || mode === '160000' || type !== 'blob') {
      warnings.push(`dependency-tree-input-not-regular-blob:${relativePath}`);
      continue;
    }
    entries.push({ mode, type, oid, path: relativePath });
    if (entries.length > maxDependencyInputs) {
      warnings.push('dependency-tree-input-count-budget-exceeded');
      entries.length = maxDependencyInputs;
      break;
    }
  }
  return { entries, warnings: [...new Set(warnings)].sort() };
}

type ExactDependencyInventory = {
  packages: DependencyIdentity[];
  warnings: string[];
  complete: boolean;
};

async function dependencyInventoryAtCommit(
  root: string,
  commit: string,
  signal?: AbortSignal
): Promise<ExactDependencyInventory> {
  const warnings = new Set<string>();
  const treeOutput = await runGitChecked(
    ['--no-replace-objects', 'ls-tree', '-r', '-z', '--full-tree', commit],
    {
      cwd: root,
      signal,
      timeoutMs: 30_000,
      maxBuffer: maxTotalBytes
    }
  );
  const listed = parseDependencyTree(treeOutput);
  listed.warnings.forEach((warning) => {
    warnings.add(warning);
  });
  const entries = listed.entries;
  const blobs = await loadBlobs(
    root,
    entries.map((entry) => entry.oid),
    signal
  );
  let bytes = 0;
  const contents = new Map<string, string>();
  for (const entry of entries) {
    const blob = blobs.get(entry.oid);
    if (!blob) {
      warnings.add(`dependency-tree-blob-unavailable:${entry.path}`);
      continue;
    }
    bytes += blob.byteLength;
    if (bytes > maxTotalBytes) {
      warnings.add('dependency-tree-byte-budget-exceeded');
      break;
    }
    if (blob.includes(0)) {
      warnings.add(`dependency-tree-input-binary:${entry.path}`);
      continue;
    }
    try {
      contents.set(
        entry.path,
        new TextDecoder('utf-8', { fatal: true }).decode(blob)
      );
    } catch {
      warnings.add(`dependency-tree-input-invalid-utf8:${entry.path}`);
    }
  }
  const fileSource: DependencyFileSource = Object.freeze({
    files: Object.freeze([...contents.keys()].sort()),
    sourceRevision: commit,
    hasFile: (relativePath) => contents.has(relativePath),
    readText: (relativePath) => contents.get(relativePath)
  });
  const packages: DependencyIdentity[] = [];
  try {
    const npm = await readNpmDependencyGraph(root, fileSource);
    packages.push(...npm.packages);
    npm.warnings.forEach((warning) => {
      warnings.add(`npm:${warning}`);
    });
    if (!npm.complete) warnings.add('npm:dependency-graph-incomplete');
    if (
      fileSource.hasFile('package.json') &&
      !fileSource.files.some((file) =>
        /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/u.test(
          file
        )
      )
    )
      warnings.add('npm:lockfile-missing-exact-versions-unknown');
  } catch (error) {
    const code =
      error && typeof error === 'object' && 'code' in error
        ? String(error.code)
        : 'unavailable';
    if (code !== 'ENOENT')
      warnings.add(`npm:dependency-graph-unavailable:${code}`);
    if (fileSource.hasFile('package.json'))
      warnings.add('npm:manifest-requirements-not-installed-identities');
  }
  const other = await readOtherEcosystemInventoryDetailed(root, fileSource);
  packages.push(...other.packages);
  other.warnings.forEach((warning) => {
    warnings.add(`other:${warning}`);
  });
  if (!other.complete) warnings.add('other:dependency-inventory-incomplete');
  return {
    packages,
    warnings: [...warnings].sort(),
    complete: warnings.size === 0
  };
}

function dependencyImpactItem(
  item: DependencyIdentity
): DependencyGraphImpactItem {
  return Object.freeze({
    ecosystem: item.ecosystem,
    name: item.name,
    version: item.version,
    direct: item.direct,
    installPath: item.installPath,
    resolutionConfidence: item.resolutionConfidence
  });
}

function publicNpmOrigin(value: string | undefined): boolean {
  try {
    const url = new URL(value ?? '');
    return (
      url.protocol === 'https:' && url.origin === 'https://registry.npmjs.org'
    );
  } catch {
    return false;
  }
}

function advisoryQueryKey(
  dependency: Pick<DependencyIdentity, 'ecosystem' | 'name' | 'version'>
): string {
  return `${dependency.ecosystem}\0${dependency.name}\0${dependency.version}`;
}

function advisoryIdentity(vulnerability: OsvVulnerability):
  | {
      id: string;
      aliases: string[];
    }
  | undefined {
  if (typeof vulnerability.id !== 'string' || !vulnerability.id.trim())
    return undefined;
  const aliases = Array.isArray(vulnerability.aliases)
    ? vulnerability.aliases.filter(
        (alias): alias is string =>
          typeof alias === 'string' && Boolean(alias.trim())
      )
    : [];
  const identifiers = [...new Set([vulnerability.id, ...aliases])].map((id) =>
    id.toUpperCase()
  );
  const id =
    identifiers
      .filter((candidate) => /^CVE-\d{4}-\d{4,}$/u.test(candidate))
      .sort()[0] ?? vulnerability.id;
  return { id, aliases: identifiers.sort() };
}

async function recomputeAdvisoryImpact(
  before: readonly DependencyIdentity[],
  after: readonly DependencyIdentity[],
  options: PrScanOptions,
  signal?: AbortSignal
): Promise<{
  status: 'complete' | 'incomplete';
  introduced: DependencyAdvisoryImpact[];
  fixed: DependencyAdvisoryImpact[];
  warnings: string[];
}> {
  const instanceKey = (item: DependencyIdentity): string =>
    [item.ecosystem, item.name, item.installPath].join('\0');
  const previous = new Map(before.map((item) => [instanceKey(item), item]));
  const current = new Map(after.map((item) => [instanceKey(item), item]));
  const changed: Array<{
    key: string;
    before?: DependencyIdentity;
    after?: DependencyIdentity;
  }> = [];
  for (const key of new Set([...previous.keys(), ...current.keys()])) {
    const oldItem = previous.get(key);
    const newItem = current.get(key);
    if (oldItem?.version !== newItem?.version)
      changed.push({ key, before: oldItem, after: newItem });
  }
  const warnings: string[] = [];
  const identities = changed.flatMap(({ before: oldItem, after: newItem }) =>
    [oldItem, newItem].filter(
      (item): item is DependencyIdentity => item !== undefined
    )
  );
  const queryInstances = new Map<string, DependencyIdentity>();
  for (const identity of identities) {
    if (
      identity.resolutionConfidence === 'unknown' ||
      identity.resolutionConfidence === 'workspace'
    ) {
      warnings.push(`advisory-resolution-unknown:${identity.ecosystem}`);
      continue;
    }
    if (
      identity.ecosystem === 'npm' &&
      (!publicNpmOrigin(identity.registry) ||
        (identity.name.startsWith('@') && !options.allowPublicScope))
    ) {
      warnings.push(
        identity.name.startsWith('@') && !options.allowPublicScope
          ? 'advisory-scoped-npm-query-withheld'
          : 'advisory-nonpublic-npm-query-withheld'
      );
      continue;
    }
    queryInstances.set(advisoryQueryKey(identity), identity);
  }
  const queries = [...queryInstances.values()].sort((left, right) =>
    advisoryQueryKey(left).localeCompare(advisoryQueryKey(right))
  );
  if (queries.length > maxPrAdvisoryQueries) {
    warnings.push('advisory-query-count-budget-exceeded');
    return {
      status: 'incomplete',
      introduced: [],
      fixed: [],
      warnings: [...new Set(warnings)].sort()
    };
  }
  if (signal?.aborted) throw signal.reason;
  const foundByQuery = new Map<string, Map<string, string[]>>();
  if (queries.length > 0) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60_000);
    const abort = (): void => controller.abort(signal?.reason);
    signal?.addEventListener('abort', abort, { once: true });
    try {
      const results = await (
        options.advisoryClient ??
        new OsvClient({
          timeoutMs: 15_000,
          batchSize: 500,
          maxResponseBytes: maxPrAdvisoryResponseBytes
        })
      ).queryBatch(
        queries.map((item) => ({
          package: { ecosystem: item.ecosystem, name: item.name },
          version: item.version
        })),
        controller.signal
      );
      if (results.length !== queries.length) {
        warnings.push('advisory-provider-response-incomplete');
      } else {
        const returnedQueries = new Set<string>();
        for (const result of results) {
          const queryKey = `${result.query.package.ecosystem}\0${result.query.package.name}\0${result.query.version}`;
          if (
            !queryInstances.has(queryKey) ||
            returnedQueries.has(queryKey) ||
            !Array.isArray(result.vulnerabilities)
          ) {
            warnings.push('advisory-provider-response-invalid');
            continue;
          }
          returnedQueries.add(queryKey);
          const vulnerabilities = new Map<string, string[]>();
          for (const vulnerability of result.vulnerabilities) {
            const identity = advisoryIdentity(vulnerability);
            if (!identity) {
              warnings.push('advisory-record-invalid');
              continue;
            }
            vulnerabilities.set(identity.id, identity.aliases);
          }
          foundByQuery.set(queryKey, vulnerabilities);
        }
        if (returnedQueries.size !== queries.length)
          warnings.push('advisory-provider-response-incomplete');
      }
    } catch (error) {
      if (signal?.aborted) throw error;
      warnings.push('advisory-provider-unavailable');
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
    }
  }
  const advisoriesFor = (
    item: DependencyIdentity | undefined
  ): Map<string, string[]> =>
    item ? (foundByQuery.get(advisoryQueryKey(item)) ?? new Map()) : new Map();
  const toImpact = (
    item: DependencyIdentity,
    advisoryId: string,
    aliases: string[]
  ): DependencyAdvisoryImpact =>
    Object.freeze({
      ecosystem: item.ecosystem,
      name: item.name,
      version: item.version,
      installPath: item.installPath,
      advisoryId,
      aliases: Object.freeze(aliases)
    });
  const introduced: DependencyAdvisoryImpact[] = [];
  const fixed: DependencyAdvisoryImpact[] = [];
  for (const change of changed) {
    const oldAdvisories = advisoriesFor(change.before);
    const newAdvisories = advisoriesFor(change.after);
    for (const [id, aliases] of newAdvisories)
      if (!oldAdvisories.has(id) && change.after)
        introduced.push(toImpact(change.after, id, aliases));
    for (const [id, aliases] of oldAdvisories)
      if (!newAdvisories.has(id) && change.before)
        fixed.push(toImpact(change.before, id, aliases));
  }
  const order = (
    left: DependencyAdvisoryImpact,
    right: DependencyAdvisoryImpact
  ) =>
    `${left.ecosystem}:${left.name}:${left.installPath}:${left.advisoryId}`.localeCompare(
      `${right.ecosystem}:${right.name}:${right.installPath}:${right.advisoryId}`
    );
  introduced.sort(order);
  fixed.sort(order);
  if (
    introduced.length > maxDependencyImpactItems ||
    fixed.length > maxDependencyImpactItems
  )
    warnings.push('advisory-output-budget-exceeded');
  return {
    status: warnings.length === 0 ? 'complete' : 'incomplete',
    introduced,
    fixed,
    warnings: [...new Set(warnings)].sort()
  };
}

async function compareDependencyInventories(
  root: string,
  base: string,
  head: string,
  signal: AbortSignal | undefined,
  options: PrScanOptions
): Promise<DependencyGraphImpact> {
  const [before, after] = await Promise.all([
    dependencyInventoryAtCommit(root, base, signal),
    dependencyInventoryAtCommit(root, head, signal)
  ]);
  const instanceKey = (item: DependencyIdentity): string =>
    [item.ecosystem, item.name, item.installPath].join('\0');
  const previous = new Map(
    before.packages.map((item) => [instanceKey(item), item])
  );
  const current = new Map(
    after.packages.map((item) => [instanceKey(item), item])
  );
  const added: DependencyGraphImpactItem[] = [];
  const removed: DependencyGraphImpactItem[] = [];
  const versionChanged: Array<{
    before: DependencyGraphImpactItem;
    after: DependencyGraphImpactItem;
  }> = [];
  for (const [key, item] of current) {
    const old = previous.get(key);
    if (!old) added.push(dependencyImpactItem(item));
    else if (old.version !== item.version)
      versionChanged.push({
        before: dependencyImpactItem(old),
        after: dependencyImpactItem(item)
      });
  }
  for (const [key, item] of previous)
    if (!current.has(key)) removed.push(dependencyImpactItem(item));
  const order = (
    left: DependencyGraphImpactItem,
    right: DependencyGraphImpactItem
  ): number =>
    `${left.ecosystem}:${left.name}:${left.installPath}:${left.version}`.localeCompare(
      `${right.ecosystem}:${right.name}:${right.installPath}:${right.version}`
    );
  added.sort(order);
  removed.sort(order);
  versionChanged.sort((left, right) => order(left.after, right.after));
  const advisory = options.onlineAdvisories
    ? await recomputeAdvisoryImpact(
        before.packages,
        after.packages,
        options,
        signal
      )
    : {
        status: 'incomplete' as const,
        introduced: [],
        fixed: [],
        warnings: ['advisory-recomputation-not-requested']
      };
  const maxItems = maxDependencyImpactItems;
  return Object.freeze({
    state: before.complete && after.complete ? 'complete' : 'incomplete',
    basePackageCount: before.packages.length,
    headPackageCount: after.packages.length,
    addedCount: added.length,
    removedCount: removed.length,
    versionChangedCount: versionChanged.length,
    added: Object.freeze(added.slice(0, maxItems)),
    removed: Object.freeze(removed.slice(0, maxItems)),
    versionChanged: Object.freeze(versionChanged.slice(0, maxItems)),
    truncated:
      added.length > maxItems ||
      removed.length > maxItems ||
      versionChanged.length > maxItems,
    warnings: Object.freeze(
      [
        ...new Set([
          ...before.warnings,
          ...after.warnings,
          ...advisory.warnings
        ])
      ].sort()
    ),
    advisoryStatus: options.onlineAdvisories
      ? advisory.status
      : 'not-recomputed',
    introducedAdvisories: Object.freeze(advisory.introduced.slice(0, maxItems)),
    fixedAdvisories: Object.freeze(advisory.fixed.slice(0, maxItems))
  });
}

function findingKeys(
  findings: readonly Finding[],
  content: string,
  normalizedPath: string
): string[] {
  const lineFingerprints = content
    .split(/\r?\n/u)
    .map((line) =>
      createHash('sha256')
        .update(line.trim().replace(/\s+/gu, ' '))
        .digest('hex')
    );
  const occurrences = new Map<string, number>();
  return findings.map((finding) => {
    const current = finding.location?.line ? finding.location.line - 1 : 0;
    const context = lineFingerprints
      .slice(
        Math.max(0, current - 1),
        Math.min(lineFingerprints.length, current + 2)
      )
      .join('\n');
    const fingerprint = createHash('sha256').update(context).digest('hex');
    const evidenceFingerprints = (finding.evidence ?? [])
      .map((evidence) => evidence.fingerprint ?? '')
      .join('\0');
    const baseKey = [
      finding.ruleId,
      finding.category,
      normalizedPath,
      finding.title,
      fingerprint,
      evidenceFingerprints
    ].join('\0');
    const occurrence = occurrences.get(baseKey) ?? 0;
    occurrences.set(baseKey, occurrence + 1);
    return `${baseKey}\0${occurrence}`;
  });
}

function scanText(filePath: string, content: string): Finding[] {
  const findings = [
    ...scanSecretContent(filePath, content),
    ...scanConfigurationContent(filePath, content)
  ];
  const extension = filePath.split('.').at(-1)?.toLowerCase() ?? '';
  if (sourceExtensions.has(extension))
    findings.push(...analyzeAstSource(filePath, content));
  return findings;
}

/**
 * Scans exact Git blobs for changed paths, comparing the same paths in the
 * baseline. Scope is deliberately always partial: unaffected repository paths,
 * dependency graph impacts, and specialized non-source analyzers are unknown.
 */
export async function scanPullRequestDiff(
  root: string,
  base: string,
  head = 'HEAD',
  signal?: AbortSignal,
  options: PrScanOptions = {}
): Promise<PrScanResult> {
  const [baseRevision, headRevision] = await Promise.all([
    resolveCommit(root, base, signal),
    resolveCommit(root, head, signal)
  ]);
  const [rawOutput, lineOutput] = await Promise.all([
    runGitChecked(
      [
        '--no-replace-objects',
        'diff',
        '--raw',
        '-z',
        '--abbrev=64',
        '-M',
        '--no-ext-diff',
        '--no-textconv',
        baseRevision.oid,
        headRevision.oid,
        '--'
      ],
      { cwd: root, signal, timeoutMs: 30_000, maxBuffer: 8 * 1024 * 1024 }
    ),
    runGitChecked(
      [
        '--no-replace-objects',
        '-c',
        'core.quotepath=false',
        'diff',
        '--unified=0',
        '--no-ext-diff',
        '--no-textconv',
        baseRevision.oid,
        headRevision.oid,
        '--'
      ],
      { cwd: root, signal, timeoutMs: 30_000, maxBuffer: maxTotalBytes }
    )
  ]);
  const changes = parseRawChanges(rawOutput);
  const reasons = new Set<string>();
  const dependencyGraphChanged = changes.some(
    (change) =>
      dependencyGraphInput.test(change.oldPath) ||
      dependencyGraphInput.test(change.newPath)
  );
  for (const change of changes) {
    if (
      hasControlCharacter(change.oldPath) ||
      hasControlCharacter(change.newPath)
    )
      reasons.add('control-character-path-requires-review');
  }
  let totalBytes = 0;
  const oids: string[] = [];
  for (const change of changes) {
    const changedPaths = [...new Set([change.oldPath, change.newPath])];
    if (change.oldOid) oids.push(change.oldOid);
    if (change.newOid) oids.push(change.newOid);
    if (change.oldMode === '120000' || change.newMode === '120000')
      reasons.add(`symlink-change:${change.newPath}`);
    if (change.oldMode === '160000' || change.newMode === '160000')
      reasons.add(`submodule-change:${change.newPath}`);
    if (dependencyGraphInput.test(change.newPath))
      reasons.add('dependency-graph-change-requires-full-scan');
    if (
      changedPaths.some(
        (changedPath) =>
          executionEntrypointPath.test(changedPath) ||
          sourceExtensions.has(
            changedPath.split('.').at(-1)?.toLowerCase() ?? ''
          )
      )
    )
      reasons.add('malicious-execution-graph-analysis-not-run');
    if (
      changedPaths.some(
        (changedPath) =>
          infrastructurePath.test(changedPath) ||
          infrastructureWorkflowPath.test(changedPath) ||
          /(?:^|\/)(?:k8s|kubernetes|manifests)\/[^/]+\.ya?ml$/iu.test(
            changedPath
          )
      )
    )
      reasons.add('infrastructure-analysis-not-run');
    if (changedPaths.some((changedPath) => policyPath.test(changedPath)))
      reasons.add('policy-effects-not-recomputed');
    for (const changedPath of changedPaths) {
      const extension = changedPath.split('.').at(-1)?.toLowerCase() ?? '';
      if (
        !sourceExtensions.has(extension) &&
        !/(?:\.env(?:\..*)?|\.(?:json|ya?ml|toml|ini|conf|cfg|tf|hcl|md)|Dockerfile(?:\..*)?)$/iu.test(
          changedPath
        )
      )
        reasons.add(`specialized-analysis-not-run:${changedPath}`);
    }
  }
  if (dependencyGraphChanged) {
    reasons.add('dependency-license-impact-not-recomputed');
    reasons.add('dependency-reachability-impact-not-recomputed');
    reasons.add('dependency-provenance-impact-not-recomputed');
    reasons.add('dependency-maintainer-impact-not-recomputed');
    reasons.add('dependency-policy-impact-not-recomputed');
  }
  const blobs = await loadBlobs(root, oids, signal);
  for (const blob of blobs.values()) {
    totalBytes += blob.length;
    if (totalBytes > maxTotalBytes)
      throw new Error('Changed Git blobs exceed the aggregate byte budget.');
  }
  const decode = (oid: string | undefined): string | undefined => {
    if (!oid) return undefined;
    const blob = blobs.get(oid);
    if (!blob) throw new Error('A changed Git blob is unavailable.');
    if (blob.includes(0)) {
      reasons.add('binary-change-requires-review');
      return undefined;
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(blob);
    } catch {
      reasons.add('non-utf8-change-requires-review');
      return undefined;
    }
  };
  const baseline = new Map<string, Finding>();
  const current = new Map<string, Finding>();
  for (const change of changes) {
    const oldText = decode(change.oldOid);
    const newText = decode(change.newOid);
    const comparisonPath = change.newPath;
    if (oldText !== undefined) {
      const findings = scanText(change.oldPath, oldText);
      const keys = findingKeys(findings, oldText, comparisonPath);
      for (let index = 0; index < findings.length; index++) {
        const finding = findings[index];
        const key = keys[index];
        if (finding && key) baseline.set(key, finding);
      }
    }
    if (newText !== undefined) {
      const findings = scanText(change.newPath, newText);
      const keys = findingKeys(findings, newText, comparisonPath);
      for (let index = 0; index < findings.length; index++) {
        const finding = findings[index];
        const key = keys[index];
        if (finding && key) current.set(key, finding);
      }
    }
  }
  const introduced = [...current]
    .filter(([key]) => !baseline.has(key))
    .map(([, finding]) => finding);
  const fixed = [...baseline]
    .filter(([key]) => !current.has(key))
    .map(([, finding]) => finding);
  const unchangedCount = [...current.keys()].filter((key) =>
    baseline.has(key)
  ).length;
  const changedLineRanges = parseChangedLineRanges(lineOutput);
  const inlineReviewComments: SafeInlineReviewComment[] = [];
  let eligibleInlineReviewComments = 0;
  for (const finding of introduced) {
    const location = finding.location;
    const path = location?.file?.replaceAll('\\', '/');
    const line = location?.line;
    if (
      !path ||
      path.startsWith('/') ||
      /^[A-Za-z]:\//u.test(path) ||
      path.split('/').some((segment) => segment === '..') ||
      hasControlCharacter(path) ||
      !Number.isSafeInteger(line) ||
      (line ?? 0) < 1 ||
      !lineIsChanged(changedLineRanges[path] ?? [], line ?? 0)
    )
      continue;
    eligibleInlineReviewComments++;
    if (inlineReviewComments.length >= maxInlineReviewComments) continue;
    const ruleId = /^[A-Za-z0-9_.:-]{1,128}$/u.test(finding.ruleId)
      ? finding.ruleId
      : 'unknown-rule';
    inlineReviewComments.push(
      Object.freeze({
        path,
        line: line ?? 0,
        ruleId,
        severity: finding.severity,
        // Never interpolate source text, excerpts, evidence or provider detail.
        body: `Toolip reports a ${finding.severity} security finding on this changed line. See the SARIF report for details; source evidence is intentionally omitted.`
      })
    );
  }
  inlineReviewComments.sort(
    (left, right) =>
      left.path.localeCompare(right.path) ||
      left.line - right.line ||
      left.ruleId.localeCompare(right.ruleId)
  );
  let dependencyImpact: DependencyGraphImpact | undefined;
  if (dependencyGraphChanged) {
    try {
      dependencyImpact = await compareDependencyInventories(
        root,
        baseRevision.oid,
        headRevision.oid,
        signal,
        options
      );
    } catch (error) {
      if (signal?.aborted) throw error;
      dependencyImpact = {
        state: 'incomplete',
        basePackageCount: 0,
        headPackageCount: 0,
        addedCount: 0,
        removedCount: 0,
        versionChangedCount: 0,
        added: [],
        removed: [],
        versionChanged: [],
        truncated: false,
        warnings: ['dependency-impact-comparison-failed'],
        advisoryStatus: 'not-recomputed',
        introducedAdvisories: [],
        fixedAdvisories: []
      };
    }
  }
  if (dependencyImpact?.state === 'incomplete')
    reasons.add('dependency-impact-comparison-incomplete');
  if (dependencyImpact?.advisoryStatus === 'not-recomputed')
    reasons.add('dependency-advisory-impact-not-recomputed');
  else if (dependencyImpact?.advisoryStatus === 'incomplete')
    reasons.add('dependency-advisory-impact-incomplete');
  return Object.freeze({
    base,
    head,
    baseCommit: baseRevision.oid,
    headCommit: headRevision.oid,
    changedFiles: Object.freeze(changes),
    changedLineRanges,
    introduced: Object.freeze(introduced),
    inlineReviewComments: Object.freeze(inlineReviewComments),
    inlineReviewCommentsTruncated:
      eligibleInlineReviewComments > inlineReviewComments.length,
    fixed: Object.freeze(fixed),
    unchangedCount,
    ...(dependencyImpact ? { dependencyImpact } : {}),
    coverage: reasons.size > 0 ? 'incomplete' : 'diff-only',
    analysisState: reasons.size > 0 ? 'failed' : 'partial',
    reasons: Object.freeze([...reasons].sort())
  });
}

/** O(log H) lookup over the sorted zero-context hunk ranges for one path. */
function lineIsChanged(ranges: readonly ChangedLineRange[], line: number) {
  let low = 0;
  let high = ranges.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    const range = ranges[middle];
    if (!range || line < range.start) high = middle;
    else if (line > range.end) low = middle + 1;
    else return true;
  }
  return false;
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

export function hasFindingAtSeverity(
  findings: readonly Finding[],
  minimum: FindingSeverity
): boolean {
  const order: Record<FindingSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  };
  return findings.some((finding) => order[finding.severity] <= order[minimum]);
}
