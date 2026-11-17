import semver from 'semver';

/**
 * Explicitly consented GitHub Advisory Database package lookup.
 *
 * This is an additional evidence source for exact npm package instances, not
 * a replacement for OSV or proof of a complete vulnerability inventory.
 * Other ecosystem version-range semantics are intentionally not guessed.
 */
export type GhsaPackageAdvisory = Readonly<{
  id: string;
  aliases: readonly string[];
  severity?: 'critical' | 'high' | 'medium' | 'low';
  reviewed: boolean;
  withdrawn: boolean;
  publishedAt?: string;
  updatedAt?: string;
  affected: 'yes' | 'no' | 'unknown';
  /** Original range is metadata only. The evaluator uses a strict parser. */
  vulnerableRange?: string;
  source: 'github-global-advisories';
  exactPackageEvidence: true;
}>;
export type GhsaPackageLookup = Readonly<{
  schema: 'toolip.dev/ghsa-npm-lookup/v1';
  packageName: string;
  version: string;
  status: 'complete' | 'partial' | 'offline' | 'failed';
  source: 'github-global-advisories';
  sourceUrl: 'https://api.github.com/advisories';
  advisories: readonly GhsaPackageAdvisory[];
  /** Empty results are never a claim that the package is vulnerability-free. */
  noVulnerabilitiesProven: false;
  reasons: readonly string[];
}>;

const packageNamePattern =
  /^(?:@[a-z0-9][a-z0-9._~-]{0,99}\/[a-z0-9][a-z0-9._~-]{0,99}|[a-z0-9][a-z0-9._~-]{0,199})$/u;
const ghsaIdPattern =
  /^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/iu;
const cveIdPattern = /^CVE-\d{4}-\d{4,}$/u;
const apiUrl = 'https://api.github.com/advisories' as const;
const maxJsonBytes = 2 * 1024 * 1024;
const maxAdvisories = 100;
const maxVulnerabilitiesPerAdvisory = 200;

function plainObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}
function isoDate(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 64) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
}
function severity(value: unknown): GhsaPackageAdvisory['severity'] {
  return value === 'critical' || value === 'high' ||
    value === 'medium' || value === 'low' ? value : undefined;
}
function fixedRange(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 256) return undefined;
  if (/[^\w.\s<>=!~^*|+\-]/u.test(value)) return undefined;
  const range = semver.validRange(value, { loose: false });
  return range !== null && range.length <= 256 ? range : undefined;
}

/** The version is exact and non-ambiguous; ranges are not installed versions. */
export function validateGhsaNpmIdentity(
  name: string,
  version: string
): void {
  if (!packageNamePattern.test(name) ||
      name !== name.toLowerCase() ||
      !semver.valid(version, { loose: false }) ||
      semver.valid(version, { loose: false }) !== version ||
      name.length > 214)
    throw new TypeError('GHSA lookup requires an exact public npm name and semver version.');
}

function matchAdvisory(
  raw: unknown,
  packageName: string,
  version: string
): GhsaPackageAdvisory | undefined {
  const value = plainObject(raw);
  const id = value?.ghsa_id;
  if (typeof id !== 'string' || !ghsaIdPattern.test(id)) return undefined;
  const vulnerabilities = value.vulnerabilities;
  if (!Array.isArray(vulnerabilities) ||
      vulnerabilities.length > maxVulnerabilitiesPerAdvisory)
    return {
      id, aliases: Object.freeze([]),
      reviewed: value.type === 'reviewed',
      withdrawn: Boolean(value.withdrawn_at),
      affected: 'unknown', source: 'github-global-advisories',
      exactPackageEvidence: true
    };
  let sawPackage = false;
  let sawUnknown = false;
  let sawAffected = false;
  let range: string | undefined;
  for (const rawEntry of vulnerabilities) {
    const entry = plainObject(rawEntry);
    const pkg = plainObject(entry?.package);
    if (pkg?.ecosystem !== 'npm' || pkg.name !== packageName) continue;
    sawPackage = true;
    const checkedRange = fixedRange(entry?.vulnerable_version_range);
    if (!checkedRange) {
      sawUnknown = true;
      continue;
    }
    range = checkedRange;
    if (semver.satisfies(version, checkedRange, { loose: false })) {
      sawAffected = true;
      break;
    }
  }
  // The global-advisory "affects" filter may include alias packages. A
  // record without this exact package identity cannot assert any result.
  if (!sawPackage) return undefined;
  const aliases = new Set<string>();
  if (typeof value.cve_id === 'string' && cveIdPattern.test(value.cve_id))
    aliases.add(value.cve_id);
  if (Array.isArray(value.identifiers)) {
    for (const identity of value.identifiers.slice(0, 32)) {
      const entry = plainObject(identity);
      if (typeof entry?.value === 'string' &&
          cveIdPattern.test(entry.value)) aliases.add(entry.value);
    }
  }
  const result: GhsaPackageAdvisory = {
    id,
    aliases: Object.freeze([...aliases].sort()),
    ...(severity(value.severity) ? { severity: severity(value.severity) } : {}),
    reviewed: value.type === 'reviewed',
    withdrawn: Boolean(value.withdrawn_at),
    ...(isoDate(value.published_at) ? { publishedAt: isoDate(value.published_at) } : {}),
    ...(isoDate(value.updated_at) ? { updatedAt: isoDate(value.updated_at) } : {}),
    affected: sawAffected ? 'yes' : sawUnknown ? 'unknown' : 'no',
    ...(range ? { vulnerableRange: range } : {}),
    source: 'github-global-advisories',
    exactPackageEvidence: true
  };
  return Object.freeze(result);
}

async function boundedGet(
  url: URL, fetcher: typeof fetch, outerSignal?: AbortSignal
): Promise<unknown> {
  if (url.origin !== 'https://api.github.com' ||
      url.pathname !== '/advisories')
    throw new Error('Untrusted advisory destination.');
  const controller = new AbortController();
  const abort = () => controller.abort();
  outerSignal?.addEventListener('abort', abort, { once: true });
  if (outerSignal?.aborted) abort();
  const timer = setTimeout(() => controller.abort(), 7_000);
  try {
    const response = await fetcher(url, {
      method: 'GET',
      redirect: 'error',
      signal: controller.signal,
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10',
        'User-Agent': 'Toolip-Explicit-GHSA-Lookup'
      }
    });
    if (!response.ok || !response.body)
      throw new Error('GitHub advisory provider is unavailable.');
    const length = response.headers.get('content-length');
    if (length && (Number(length) > maxJsonBytes ||
        !Number.isSafeInteger(Number(length))))
      throw new Error('GitHub advisory response exceeds byte budget.');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        bytes += next.value.byteLength;
        if (bytes > maxJsonBytes)
          throw new Error('GitHub advisory response exceeds byte budget.');
        chunks.push(next.value);
      }
    } finally {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true })
      .decode(Buffer.concat(chunks, bytes))) as unknown;
  } finally {
    clearTimeout(timer);
    outerSignal?.removeEventListener('abort', abort);
  }
}

/**
 * One bounded provider request for a publicly named exact npm instance.
 * "complete" means this one provider response was inspected, not that all
 * GHSA pages or all advisory sources were exhaustively searched.
 */
export async function lookupGhsaNpmPackage(
  packageName: string,
  version: string,
  options: Readonly<{
    offline?: boolean;
    allowPublicPackageLookup?: boolean;
    signal?: AbortSignal;
    fetcher?: typeof fetch;
  }> = {}
): Promise<GhsaPackageLookup> {
  validateGhsaNpmIdentity(packageName, version);
  const baseline = {
    schema: 'toolip.dev/ghsa-npm-lookup/v1' as const,
    packageName, version, source: 'github-global-advisories' as const,
    sourceUrl: apiUrl,
    noVulnerabilitiesProven: false as const
  };
  if (options.offline || options.allowPublicPackageLookup !== true) {
    return Object.freeze({
      ...baseline,
      status: 'offline' as const,
      advisories: Object.freeze([]),
      reasons: Object.freeze([
        'This package lookup did not contact GitHub; consent and online mode are required.'
      ])
    });
  }
  const url = new URL(apiUrl);
  url.searchParams.set('ecosystem', 'npm');
  url.searchParams.set('affects', packageName);
  url.searchParams.set('per_page', String(maxAdvisories));
  let parsed: unknown;
  try {
    parsed = await boundedGet(url, options.fetcher ?? fetch, options.signal);
  } catch {
    return Object.freeze({
      ...baseline,
      status: 'failed' as const,
      advisories: Object.freeze([]),
      reasons: Object.freeze(['GitHub advisory request failed or returned invalid data.'])
    });
  }
  if (!Array.isArray(parsed) || parsed.length > maxAdvisories)
    return Object.freeze({
      ...baseline,
      status: 'failed' as const,
      advisories: Object.freeze([]),
      reasons: Object.freeze(['GitHub advisory response is not an accepted bounded list.'])
    });
  const found = new Map<string, GhsaPackageAdvisory>();
  let malformed = false;
  for (const value of parsed) {
    const item = matchAdvisory(value, packageName, version);
    if (!item) {
      malformed = true;
      continue;
    }
    const key = item.id.toUpperCase();
    if (found.has(key)) {
      malformed = true;
      continue;
    }
    found.set(key, item);
  }
  const advisories = Object.freeze(
    [...found.values()].sort((a, b) => a.id.localeCompare(b.id))
  );
  const partial = malformed || parsed.length === maxAdvisories ||
    advisories.some((item) => item.affected === 'unknown');
  return Object.freeze({
    ...baseline,
    status: partial ? 'partial' as const : 'complete' as const,
    advisories,
    reasons: Object.freeze([
      ...(malformed ? ['Some provider records did not match the exact package or were malformed.'] : []),
      ...(parsed.length === maxAdvisories ? ['First GHSA page reached its limit; more advisories may exist.'] : []),
      ...(advisories.some((item) => item.affected === 'unknown')
        ? ['Some GHSA ranges could not be interpreted as strict npm semver.'] : []),
      'Only GHSA range claims are evaluated; other sources, package aliases and offline data remain outside this lookup.'
    ])
  });
}
