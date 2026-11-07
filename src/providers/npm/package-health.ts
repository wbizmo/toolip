import { createHash } from 'node:crypto';
import { mapConcurrent } from '../../application/concurrency.js';

const ENDPOINT = 'https://registry.npmjs.org';
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_VERSIONS = 10_000;
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const PACKAGE_NAME_PATTERN = /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/u;

type Packument = {
  name?: unknown;
  'dist-tags'?: unknown;
  time?: unknown;
  maintainers?: unknown;
  repository?: unknown;
  versions?: unknown;
};

export type PackageHealthSignal = {
  id:
    | 'publisher-identity-varies'
    | 'release-burst'
    | 'stale-maintenance'
    | 'maintainer-set-varies'
    | 'new-install-script'
    | 'repository-identity-changed'
    | 'package-deprecated';
  source: 'npm-registry';
  observedAt: string;
  confidence: 'low' | 'medium';
  evidence: string;
};

export type NpmPackageHealth = {
  package: string;
  installedVersion: string;
  status: 'available' | 'unavailable' | 'not_queried';
  registry: typeof ENDPOINT;
  fetchedAt?: string;
  lastPublishedAt?: string;
  deprecated?: boolean;
  maintainersObserved?: number;
  maintainerHistoryStatus: 'observed' | 'unavailable';
  publisherHistoryStatus: 'observed' | 'unavailable';
  publisherChangesObserved?: number;
  releaseHistoryStatus: 'observed' | 'unavailable';
  releaseCount7Days?: number;
  installScripts?: string[];
  sourceRepository?: string;
  signals: PackageHealthSignal[];
  warnings: string[];
};

type NpmHealthOptions = {
  fetchImplementation?: typeof fetch;
  now?: () => Date;
  random?: () => number;
  requestTimeoutMs?: number;
  allowScopedPublicPackage?: boolean;
  offline?: boolean;
  concurrency?: number;
};

export type NpmPackageIdentity = {
  name: string;
  version: string;
  installPath: string;
  /** Resolved lockfile registry; missing or custom origins are never sent to npmjs. */
  registry?: string;
};

export type NpmPackageHealthObservation = NpmPackageIdentity & {
  health: NpmPackageHealth;
};

type CacheEntry = { expiresAt: number; value: NpmPackageHealth };

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function normalizedRepository(value: unknown): string | undefined {
  const url =
    typeof value === 'string'
      ? value
      : isRecord(value) && typeof value.url === 'string'
        ? value.url
        : undefined;
  if (!url) return undefined;
  const normalized = url
    .trim()
    .replace(/^git\+|^git:/u, '')
    .replace(/\.git$/iu, '')
    .replace(/^github:/u, 'https://github.com/')
    .replace(/^gitlab:/u, 'https://gitlab.com/')
    .replace(/^bitbucket:/u, 'https://bitbucket.org/')
    .replace(/\.git#.*$/iu, '')
    .replace(/#.*$/u, '')
    .replace(/\/+$/u, '');
  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
      return undefined;
    return `${parsed.hostname.toLowerCase()}${parsed.pathname.replace(/\/+$/u, '').toLowerCase()}`;
  } catch {
    return undefined;
  }
}

function scriptNames(value: unknown): string[] {
  if (!isRecord(value)) return [];
  return Object.keys(value)
    .filter((name) =>
      ['preinstall', 'install', 'postinstall', 'prepare'].includes(name)
    )
    .sort();
}

function publisher(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  const identity = value._npmUser;
  return isRecord(identity) && typeof identity.name === 'string'
    ? identity.name.slice(0, 128)
    : undefined;
}

function maintainerSet(value: unknown): string | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  const identities = value
    .flatMap((entry) => {
      if (!isRecord(entry)) return [];
      const name = typeof entry.name === 'string' ? entry.name.trim() : '';
      const email = typeof entry.email === 'string' ? entry.email.trim() : '';
      const identity = `${name.toLowerCase()}\0${email.toLowerCase()}`;
      return name || email ? [identity] : [];
    })
    .sort();
  if (identities.length === 0) return undefined;
  return createHash('sha256').update(identities.join('\0')).digest('hex');
}

async function boundedJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('registry-response-empty');
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('registry-response-too-large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(
    chunks.map((chunk) => Buffer.from(chunk)),
    total
  );
  return JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  ) as unknown;
}

function wait(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(abortError());
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function abortError(): Error {
  const error = new Error('Package health lookup was cancelled.');
  error.name = 'AbortError';
  return error;
}

/** Bounded npm packument analysis; publisher changes are review signals, never malicious verdicts. */
export class NpmPackageHealthClient {
  private readonly cache = new Map<string, CacheEntry>();

  constructor(private readonly options: NpmHealthOptions = {}) {}

  async inspect(
    packageName: string,
    installedVersion: string,
    signal?: AbortSignal,
    registry = ENDPOINT
  ): Promise<NpmPackageHealth> {
    if (!PACKAGE_NAME_PATTERN.test(packageName) || packageName.length > 214) {
      return this.unknown(
        packageName,
        installedVersion,
        'invalid-package-identity'
      );
    }
    if (packageName.startsWith('@') && !this.options.allowScopedPublicPackage) {
      return this.unknown(
        packageName,
        installedVersion,
        'scoped-name-not-queried'
      );
    }
    if (!isPublicNpmRegistry(registry)) {
      return this.unknown(
        packageName,
        installedVersion,
        'registry-identity-not-public-npm'
      );
    }
    if (signal?.aborted) throw abortError();
    if (installedVersion.length === 0 || installedVersion.length > 256) {
      return this.unknown(
        packageName,
        installedVersion,
        'invalid-installed-version'
      );
    }
    const cacheKey = `${new URL(registry).origin}\0${packageName}\0${installedVersion}`;
    const cached = this.cache.get(cacheKey);
    const now = this.options.now ?? (() => new Date());
    if (cached && cached.expiresAt > now().getTime())
      return structuredClone(cached.value);
    this.cache.delete(cacheKey);
    if (this.options.offline) {
      return this.unknown(packageName, installedVersion, 'offline-cache-miss');
    }

    try {
      const packument = await this.fetchPackument(packageName, signal);
      const result = this.analyze(
        packument,
        packageName,
        installedVersion,
        now()
      );
      if (this.cache.size >= 1000) {
        const oldest = this.cache.keys().next().value as string | undefined;
        if (oldest !== undefined) this.cache.delete(oldest);
      }
      this.cache.set(cacheKey, {
        expiresAt: now().getTime() + CACHE_TTL_MS,
        value: result
      });
      return structuredClone(result);
    } catch (error) {
      if (
        signal?.aborted ||
        (error instanceof Error && error.name === 'AbortError')
      )
        throw abortError();
      return this.unknown(
        packageName,
        installedVersion,
        providerFailureReason(error)
      );
    }
  }

  /** Deduplicates exact name/version provider calls and maps them to each install path. */
  async inspectMany(
    dependencies: NpmPackageIdentity[],
    signal?: AbortSignal
  ): Promise<NpmPackageHealthObservation[]> {
    if (dependencies.length > 1000)
      throw new Error('package-health-batch-limit-exceeded');
    const unique = new Map<string, NpmPackageIdentity>();
    for (const dependency of dependencies) {
      const key = `${dependency.registry ?? 'unknown'}\0${dependency.name}\0${dependency.version}`;
      if (!unique.has(key)) unique.set(key, dependency);
    }
    const results = await mapConcurrent(
      [...unique.entries()],
      this.options.concurrency ?? 6,
      async ([key, dependency]) =>
        [
          key,
          await this.inspect(
            dependency.name,
            dependency.version,
            signal,
            dependency.registry ?? ''
          )
        ] as const
    );
    const byVersion = new Map(results);
    return dependencies.map((dependency) => ({
      ...dependency,
      health:
        byVersion.get(
          `${dependency.registry ?? 'unknown'}\0${dependency.name}\0${dependency.version}`
        ) ??
        this.unknown(
          dependency.name,
          dependency.version,
          'provider-result-missing'
        )
    }));
  }

  private async fetchPackument(
    packageName: string,
    signal?: AbortSignal
  ): Promise<Packument> {
    const url = new URL(encodeURIComponent(packageName), `${ENDPOINT}/`);
    const endpoint = new URL(ENDPOINT);
    const fetchImplementation =
      this.options.fetchImplementation ?? globalThis.fetch;
    const random = this.options.random ?? Math.random;
    for (let attempt = 0; attempt < 3; attempt++) {
      if (signal?.aborted) throw abortError();
      const controller = new AbortController();
      const abortOuter = (): void => controller.abort();
      signal?.addEventListener('abort', abortOuter, { once: true });
      let response: Response | undefined;
      try {
        let rejectTimeout: ((reason: Error) => void) | undefined;
        const timeoutPromise = new Promise<never>((_resolve, reject) => {
          rejectTimeout = reject;
        });
        const deadline = setTimeout(() => {
          controller.abort();
          rejectTimeout?.(new Error('registry-request-timeout'));
        }, this.options.requestTimeoutMs ?? 5_000);
        try {
          const body = await Promise.race([
            (async () => {
              response = await fetchImplementation(url, {
                headers: {
                  accept: 'application/vnd.npm.install-v1+json',
                  'user-agent': 'toolip'
                },
                redirect: 'error',
                signal: controller.signal
              });
              if (
                response.url &&
                new URL(response.url).origin !== endpoint.origin
              )
                throw new Error('registry-origin-changed');
              if (response.status === 429 || response.status >= 500) {
                await response.body?.cancel().catch(() => undefined);
                throw new Error(`registry-http-${response.status}`);
              }
              if (!response.ok)
                throw new Error(`registry-http-${response.status}`);
              return await boundedJson(response);
            })(),
            timeoutPromise
          ]);
          if (!isRecord(body)) throw new Error('registry-packument-invalid');
          return body as Packument;
        } finally {
          clearTimeout(deadline);
        }
      } catch (error) {
        if (signal?.aborted) throw abortError();
        if (response && (response.status === 429 || response.status >= 500)) {
          if (attempt === 2)
            throw new Error(`registry-http-${response.status}`);
          await wait(250 * 2 ** attempt + Math.floor(random() * 100), signal);
          continue;
        }
        if (response && !response.ok) {
          throw new Error(`registry-http-${response.status}`);
        }
        if (controller.signal.aborted && attempt === 2)
          throw new Error('registry-request-timeout');
        if (attempt === 2) throw error;
        if (error instanceof SyntaxError)
          throw new Error('registry-json-invalid');
        await wait(250 * 2 ** attempt + Math.floor(random() * 100), signal);
      } finally {
        signal?.removeEventListener('abort', abortOuter);
      }
    }
    throw new Error('registry-retries-exhausted');
  }

  private analyze(
    packument: Packument,
    packageName: string,
    installedVersion: string,
    now: Date
  ): NpmPackageHealth {
    const versions = packument.versions;
    const times = packument.time;
    if (
      packument.name !== packageName ||
      !isRecord(versions) ||
      Object.keys(versions).length === 0 ||
      Object.keys(versions).length > MAX_VERSIONS ||
      !isRecord(times)
    ) {
      throw new Error('registry-packument-invalid');
    }
    const tags = isRecord(packument['dist-tags']) ? packument['dist-tags'] : {};
    const latest = typeof tags.latest === 'string' ? tags.latest : undefined;
    const installed = versions[installedVersion];
    const latestVersion = latest ? versions[latest] : undefined;
    if (!isRecord(installed)) throw new Error('installed-version-not-found');

    const published = Object.entries(times)
      .flatMap(([version, date]) => {
        if (version === 'created' || version === 'modified' || !isDate(date)) {
          return [];
        }
        const timestamp = Date.parse(date);
        return timestamp <= now.getTime() ? [{ version, date: timestamp }] : [];
      })
      .sort(
        (left, right) =>
          left.date - right.date || left.version.localeCompare(right.version)
      );
    const lastPublished = published.at(-1);
    const lastSevenDays = published.filter(
      (release) => now.getTime() - release.date <= 7 * 86_400_000
    );
    const recentPublisherIds = published
      .slice(-5)
      .map((release) => publisher(versions[release.version]))
      .filter((value): value is string => Boolean(value));
    const historicalMaintainerSets = published
      .slice(-5)
      .map((release) => {
        const metadata = versions[release.version];
        return isRecord(metadata)
          ? maintainerSet(metadata.maintainers)
          : undefined;
      })
      .filter((value): value is string => Boolean(value));
    const publisherChanges =
      recentPublisherIds.length >= 2
        ? recentPublisherIds
            .slice(1)
            .filter((value, index) => value !== recentPublisherIds[index])
            .length
        : undefined;
    const maintainerCount = Array.isArray(packument.maintainers)
      ? packument.maintainers.filter(
          (entry) => isRecord(entry) && typeof entry.name === 'string'
        ).length
      : undefined;
    const repository = normalizedRepository(installed.repository);
    const latestRepository = isRecord(latestVersion)
      ? normalizedRepository(latestVersion.repository)
      : undefined;
    const scripts = scriptNames(installed.scripts);
    const installedIndex = published.findIndex(
      (release) => release.version === installedVersion
    );
    const priorVersion =
      installedIndex > 0 ? published[installedIndex - 1] : undefined;
    const priorScripts =
      priorVersion && isRecord(versions[priorVersion.version])
        ? scriptNames(
            (versions[priorVersion.version] as Record<string, unknown>).scripts
          )
        : [];
    const signals: PackageHealthSignal[] = [];
    const observedAt = now.toISOString();
    if (publisherChanges !== undefined && publisherChanges > 0) {
      signals.push({
        id: 'publisher-identity-varies',
        source: 'npm-registry',
        observedAt,
        confidence: 'low',
        evidence: `Different npm publisher identities appear across the latest ${Math.min(5, recentPublisherIds.length)} recorded releases; this is a review signal, not an ownership or compromise determination.`
      });
    }
    const maintainerHistoryVaries = new Set(historicalMaintainerSets).size > 1;
    if (maintainerHistoryVaries) {
      signals.push({
        id: 'maintainer-set-varies',
        source: 'npm-registry',
        observedAt,
        confidence: 'low',
        evidence:
          'Maintainer identity sets differ across published version metadata; registry history is incomplete and this signal is not an ownership or compromise determination.'
      });
    }
    if (lastSevenDays.length > 10) {
      signals.push({
        id: 'release-burst',
        source: 'npm-registry',
        observedAt,
        confidence: 'low',
        evidence: `${lastSevenDays.length} releases were recorded in the last seven days; package-specific release practices require review.`
      });
    }
    if (
      lastPublished &&
      now.getTime() - lastPublished.date > 365 * 86_400_000
    ) {
      signals.push({
        id: 'stale-maintenance',
        source: 'npm-registry',
        observedAt,
        confidence: 'low',
        evidence:
          'No release was recorded in the last 365 days; maintenance activity should be reviewed in context.'
      });
    }
    if (scripts.some((name) => !priorScripts.includes(name))) {
      signals.push({
        id: 'new-install-script',
        source: 'npm-registry',
        observedAt,
        confidence: 'medium',
        evidence: `Installed version introduces lifecycle script(s): ${scripts.filter((name) => !priorScripts.includes(name)).join(', ')}.`
      });
    }
    if (repository && latestRepository && repository !== latestRepository) {
      signals.push({
        id: 'repository-identity-changed',
        source: 'npm-registry',
        observedAt,
        confidence: 'low',
        evidence:
          'The repository identity differs between the installed and latest published versions.'
      });
    }
    const deprecated = Boolean(installed.deprecated);
    if (deprecated) {
      signals.push({
        id: 'package-deprecated',
        source: 'npm-registry',
        observedAt,
        confidence: 'medium',
        evidence:
          'The exact installed version is marked deprecated in the npm registry.'
      });
    }
    return {
      package: packageName,
      installedVersion,
      status: 'available',
      registry: ENDPOINT,
      fetchedAt: observedAt,
      lastPublishedAt: lastPublished
        ? new Date(lastPublished.date).toISOString()
        : undefined,
      deprecated,
      maintainersObserved: maintainerCount,
      maintainerHistoryStatus:
        historicalMaintainerSets.length >= 2 ? 'observed' : 'unavailable',
      publisherHistoryStatus:
        publisherChanges === undefined ? 'unavailable' : 'observed',
      publisherChangesObserved: publisherChanges,
      releaseHistoryStatus: published.length === 0 ? 'unavailable' : 'observed',
      releaseCount7Days:
        published.length === 0 ? undefined : lastSevenDays.length,
      installScripts: scripts,
      sourceRepository: repository,
      signals,
      warnings: []
    };
  }

  private unknown(
    packageName: string,
    installedVersion: string,
    reason: string
  ): NpmPackageHealth {
    return {
      package: packageName,
      installedVersion,
      status:
        reason === 'scoped-name-not-queried' ||
        reason === 'offline-cache-miss' ||
        reason === 'registry-identity-not-public-npm'
          ? 'not_queried'
          : 'unavailable',
      registry: ENDPOINT,
      publisherHistoryStatus: 'unavailable',
      maintainerHistoryStatus: 'unavailable',
      releaseHistoryStatus: 'unavailable',
      signals: [],
      warnings: [reason]
    };
  }
}

function isPublicNpmRegistry(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === ENDPOINT;
  } catch {
    return false;
  }
}

function isDate(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function providerFailureReason(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^registry-http-\d{3}$/u.test(message)) return message;
  if (
    [
      'registry-request-timeout',
      'registry-origin-changed',
      'registry-response-empty',
      'registry-response-too-large',
      'registry-packument-invalid',
      'registry-json-invalid',
      'installed-version-not-found'
    ].includes(message)
  ) {
    return message;
  }
  return 'registry-provider-unavailable';
}
