/** Public CVE enrichment only. It does not resolve package identities or
 * claim that a CPE range proves an installed package is vulnerable.
 */
export type AdvisorySource = 'ghsa' | 'nvd';
export type AdvisoryClaim = Readonly<{
  source: AdvisorySource;
  id: string;
  aliases: readonly string[];
  published?: string;
  modified?: string;
  withdrawn?: string;
  severity?: string;
  cvssScore?: number;
  cwes?: readonly string[];
  packageEcosystems?: readonly string[];
  reviewed?: boolean;
  cpeIsPackageEvidence: false;
}>;

export type CveEnrichment = Readonly<{
  cveId: string;
  status: 'complete' | 'partial' | 'offline' | 'failed';
  claims: readonly AdvisoryClaim[];
  sourceStatus: Readonly<{
    ghsa: 'complete' | 'failed' | 'offline';
    nvd: 'complete' | 'failed' | 'offline';
  }>;
  reasons: readonly string[];
}>;

const cvePattern = /^CVE-\d{4}-\d{4,}$/u;
const ghsaPattern = /^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/iu;
const maxJsonBytes = 2 * 1024 * 1024;

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function iso(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 64 ||
      !Number.isFinite(Date.parse(value))) return undefined;
  return new Date(Date.parse(value)).toISOString();
}

function cvss(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) ||
      value < 0 || value > 10) return undefined;
  return value;
}

async function getJson(
  url: URL, fetcher: typeof fetch, signal?: AbortSignal
): Promise<unknown> {
  const timeout = new AbortController();
  const onAbort = () => timeout.abort(signal?.reason);
  signal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => timeout.abort(), 7_000);
  try {
    const response = await fetcher(url, {
      method: 'GET', redirect: 'error', signal: timeout.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'Toolip-Advisory-Enrichment',
        ...(url.hostname === 'api.github.com'
          ? { 'X-GitHub-Api-Version': '2026-03-10' }
          : {})
      }
    });
    if (!response.ok) throw new Error('Advisory provider did not return success.');
    if (!response.body) throw new Error('Advisory response is empty.');
    if (Number(response.headers.get('content-length')) > maxJsonBytes)
      throw new RangeError('Advisory response exceeds maximum bytes.');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const result = await reader.read();
        if (result.done) break;
        size += result.value.byteLength;
        if (size > maxJsonBytes)
          throw new RangeError('Advisory response exceeds maximum bytes.');
        chunks.push(result.value);
      }
    } finally {
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
    return JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size))
    ) as unknown;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

function fromGhsa(cveId: string, raw: unknown): AdvisoryClaim[] {
  if (!Array.isArray(raw) || raw.length > 100)
    throw new TypeError('Invalid GitHub advisory list.');
  const result: AdvisoryClaim[] = [];
  for (const item of raw) {
    const value = record(item);
    if (!value || value.cve_id !== cveId ||
        typeof value.ghsa_id !== 'string' ||
        !ghsaPattern.test(value.ghsa_id)) continue;
    const versions = Array.isArray(value.vulnerabilities)
      ? value.vulnerabilities.slice(0, 100)
      : [];
    const ecosystems = new Set<string>();
    for (const version of versions) {
      const ecosystem = record(record(version)?.package)?.ecosystem;
      if (typeof ecosystem === 'string' && ecosystem.length <= 32)
        ecosystems.add(ecosystem);
    }
    result.push({
      source: 'ghsa',
      id: value.ghsa_id,
      aliases: Object.freeze([cveId]),
      ...(iso(value.published_at) ? { published: iso(value.published_at) } : {}),
      ...(iso(value.updated_at) ? { modified: iso(value.updated_at) } : {}),
      ...(iso(value.withdrawn_at) ? { withdrawn: iso(value.withdrawn_at) } : {}),
      ...(typeof value.severity === 'string'
        ? { severity: value.severity.slice(0, 20) }
        : {}),
      ...(cvss(record(value.cvss)?.score) !== undefined
        ? { cvssScore: cvss(record(value.cvss)?.score) }
        : {}),
      packageEcosystems: Object.freeze([...ecosystems].sort()),
      reviewed: value.type === 'reviewed',
      cpeIsPackageEvidence: false
    });
  }
  return result;
}

function fromNvd(cveId: string, raw: unknown): AdvisoryClaim[] {
  const list = record(raw)?.vulnerabilities;
  if (!Array.isArray(list) || list.length > 20)
    throw new TypeError('Invalid NVD CVE response.');
  const claims: AdvisoryClaim[] = [];
  for (const item of list) {
    const cve = record(record(item)?.cve);
    if (!cve || cve.id !== cveId) continue;
    const metrics = record(cve.metrics);
    const metricFamilies = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
    let severity: string | undefined;
    let score: number | undefined;
    for (const family of metricFamilies) {
      const entries = metrics?.[family];
      if (!Array.isArray(entries) || entries.length === 0) continue;
      for (const candidate of entries.slice(0, 32)) {
        const metric = record(candidate);
        const data = record(metric?.cvssData);
        const found = cvss(data?.baseScore);
        if (found === undefined) continue;
        score = found;
        severity = typeof data?.baseSeverity === 'string'
          ? data.baseSeverity.slice(0, 20)
          : typeof metric?.baseSeverity === 'string'
            ? metric.baseSeverity.slice(0, 20)
            : undefined;
        break;
      }
      if (score !== undefined) break;
    }
    const weaknesses = Array.isArray(cve.weaknesses)
      ? cve.weaknesses.slice(0, 128)
      : [];
    const cwes = new Set<string>();
    for (const item of weaknesses) {
      const descriptions = record(item)?.description;
      if (!Array.isArray(descriptions)) continue;
      for (const part of descriptions.slice(0, 16)) {
        const code = record(part)?.value;
        if (typeof code === 'string' && /^CWE-\d+$/u.test(code)) cwes.add(code);
      }
    }
    claims.push({
      source: 'nvd',
      id: cveId,
      aliases: Object.freeze([]),
      ...(iso(cve.published) ? { published: iso(cve.published) } : {}),
      ...(iso(cve.lastModified) ? { modified: iso(cve.lastModified) } : {}),
      ...(severity ? { severity } : {}),
      ...(score !== undefined ? { cvssScore: score } : {}),
      cwes: Object.freeze([...cwes].sort()),
      cpeIsPackageEvidence: false
    });
  }
  return claims;
}

/** Each source retains its own assertions. Missing data is partial, not safe. */
export async function enrichCve(
  cveId: string,
  options: {
    offline?: boolean;
    allowPublicCveLookup?: boolean;
    signal?: AbortSignal;
    fetcher?: typeof fetch;
  } = {}
): Promise<CveEnrichment> {
  if (!cvePattern.test(cveId) || cveId.length > 40)
    throw new TypeError('CVE identifier is invalid.');
  if (options.offline || !options.allowPublicCveLookup) {
    return {
      cveId, status: 'offline', claims: [],
      sourceStatus: { ghsa: 'offline', nvd: 'offline' },
      reasons: ['Public CVE enrichment was not explicitly authorized.']
    };
  }
  const fetcher = options.fetcher ?? fetch;
  const ghsa = new URL('https://api.github.com/advisories');
  ghsa.searchParams.set('cve_id', cveId);
  ghsa.searchParams.set('per_page', '100');
  const nvd = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
  nvd.searchParams.set('cveId', cveId);
  const calls = await Promise.allSettled([
    getJson(ghsa, fetcher, options.signal).then((value) => fromGhsa(cveId, value)),
    getJson(nvd, fetcher, options.signal).then((value) => fromNvd(cveId, value))
  ]);
  const sourceStatus = {
    ghsa: calls[0]?.status === 'fulfilled' ? 'complete' as const : 'failed' as const,
    nvd: calls[1]?.status === 'fulfilled' ? 'complete' as const : 'failed' as const
  };
  const claims = calls.flatMap((call) =>
    call.status === 'fulfilled' ? call.value : []
  );
  const complete = sourceStatus.ghsa === 'complete' && sourceStatus.nvd === 'complete';
  return {
    cveId,
    status: complete ? 'complete' : claims.length > 0 ? 'partial' : 'failed',
    claims: Object.freeze(claims),
    sourceStatus: Object.freeze(sourceStatus),
    reasons: Object.freeze([
      ...(sourceStatus.ghsa === 'failed' ? ['GHSA provider failed or returned invalid data.'] : []),
      ...(sourceStatus.nvd === 'failed' ? ['NVD provider failed or returned invalid data.'] : []),
      'CPE data is not authoritative evidence of installed package versions.'
    ])
  };
}
