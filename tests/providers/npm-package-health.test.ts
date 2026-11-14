import { describe, expect, it, vi } from 'vitest';
import {
  NpmPackageHealthClient,
  type NpmPackageIdentity
} from '../../src/providers/npm/package-health.js';

function packument(overrides: Record<string, unknown> = {}): Response {
  const now = new Date('2026-11-06T12:00:00.000Z');
  const json = {
    name: 'safe-package',
    'dist-tags': { latest: '2.0.0' },
    maintainers: [{ name: 'maintainer-a', email: 'private@example.invalid' }],
    repository: { url: 'git+https://github.com/acme/safe-package.git' },
    time: {
      created: '2024-01-01T00:00:00.000Z',
      '1.0.0': new Date(now.getTime() - 9 * 86_400_000).toISOString(),
      '1.1.0': new Date(now.getTime() - 3 * 86_400_000).toISOString(),
      '1.2.0': new Date(now.getTime() - 2 * 86_400_000).toISOString(),
      '1.3.0': new Date(now.getTime() - 86_400_000).toISOString(),
      '2.0.0': now.toISOString()
    },
    versions: {
      '1.0.0': {
        _npmUser: { name: 'publisher-a' },
        maintainers: [{ name: 'maintainer-old' }],
        scripts: {}
      },
      '1.1.0': {
        _npmUser: { name: 'publisher-b' },
        maintainers: [{ name: 'maintainer-old' }],
        scripts: {}
      },
      '1.2.0': {
        _npmUser: { name: 'publisher-b' },
        maintainers: [{ name: 'maintainer-new' }],
        scripts: {}
      },
      '1.3.0': {
        _npmUser: { name: 'publisher-b' },
        repository: { url: 'https://github.com/acme/safe-package' },
        scripts: { postinstall: 'node install.js' }
      },
      '2.0.0': {
        _npmUser: { name: 'publisher-b' },
        repository: { url: 'https://github.com/other/project' },
        scripts: { postinstall: 'node install.js' }
      }
    },
    ...overrides
  };
  return new Response(JSON.stringify(json), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  });
}

describe('NpmPackageHealthClient', () => {
  it('does not query scoped packages unless public disclosure is opted in', async () => {
    const fetchImplementation = vi.fn<typeof fetch>();
    const client = new NpmPackageHealthClient({ fetchImplementation });

    const result = await client.inspect('@private/pkg', '1.2.3');

    expect(result.status).toBe('not_queried');
    expect(result.warnings).toContain('scoped-name-not-queried');
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('emits review signals without treating metadata as a compromise verdict', async () => {
    const fetchImplementation = vi.fn<typeof fetch>(async () => packument());
    const client = new NpmPackageHealthClient({
      fetchImplementation,
      now: () => new Date('2026-11-06T12:00:00.000Z')
    });

    const result = await client.inspect('safe-package', '1.3.0');

    expect(result.status).toBe('available');
    expect(result.publisherChangesObserved).toBeGreaterThan(0);
    expect(result.maintainerHistoryStatus).toBe('partial');
    expect(result.warnings).toContain('npm-maintainer-history-incomplete');
    expect(result.publisherEvents).toEqual([
      {
        package: 'safe-package',
        version: '1.0.0',
        registry: 'https://registry.npmjs.org',
        publishedAt: '2026-10-28T12:00:00.000Z',
        publisherIdentitySha256:
          'a6f29c1b3fce7290a91d3907d3156d13bd2b67121e176021db2193e750477f19',
        confidence: 'low'
      },
      {
        package: 'safe-package',
        version: '1.1.0',
        registry: 'https://registry.npmjs.org',
        publishedAt: '2026-11-03T12:00:00.000Z',
        publisherIdentitySha256:
          '7806545fdd7b02a70ec5c67c2da7f8f4f65771881becdc615c43214baab73fbb',
        confidence: 'low'
      },
      {
        package: 'safe-package',
        version: '1.2.0',
        registry: 'https://registry.npmjs.org',
        publishedAt: '2026-11-04T12:00:00.000Z',
        publisherIdentitySha256:
          '7806545fdd7b02a70ec5c67c2da7f8f4f65771881becdc615c43214baab73fbb',
        confidence: 'low'
      },
      {
        package: 'safe-package',
        version: '1.3.0',
        registry: 'https://registry.npmjs.org',
        publishedAt: '2026-11-05T12:00:00.000Z',
        publisherIdentitySha256:
          '7806545fdd7b02a70ec5c67c2da7f8f4f65771881becdc615c43214baab73fbb',
        confidence: 'low'
      },
      {
        package: 'safe-package',
        version: '2.0.0',
        registry: 'https://registry.npmjs.org',
        publishedAt: '2026-11-06T12:00:00.000Z',
        publisherIdentitySha256:
          '7806545fdd7b02a70ec5c67c2da7f8f4f65771881becdc615c43214baab73fbb',
        confidence: 'low'
      }
    ]);
    expect(result.maintainerEvents).toHaveLength(3);
    expect(
      result.publisherEvents?.every(
        (event) =>
          event.package === result.package && event.registry === result.registry
      )
    ).toBe(true);
    expect(result.releaseCount7Days).toBe(4);
    expect(result.installScripts).toContain('postinstall');
    expect(result.signals.map(({ id }) => id)).toEqual(
      expect.arrayContaining([
        'publisher-identity-varies',
        'maintainer-set-varies',
        'new-install-script',
        'repository-identity-changed'
      ])
    );
    expect(JSON.stringify(result)).not.toContain('private@example.invalid');
    expect(JSON.stringify(result)).not.toContain('publisher-a');
    expect(result.status).not.toBe('malicious');
    expect(
      result.signals.every(({ confidence }) => confidence !== 'high')
    ).toBe(true);
  });

  it('keeps exact versions distinct and respects freshness cache', async () => {
    const fetchImplementation = vi.fn<typeof fetch>(async () => packument());
    let current = new Date('2026-11-06T12:00:00.000Z');
    const client = new NpmPackageHealthClient({
      fetchImplementation,
      now: () => current
    });

    const first = await client.inspect('safe-package', '1.3.0');
    first.signals.push({
      id: 'package-deprecated',
      source: 'npm-registry',
      observedAt: '2026-11-06T12:00:00.000Z',
      confidence: 'medium',
      evidence: 'caller mutation'
    });
    const cached = await client.inspect('safe-package', '1.3.0');
    expect(
      cached.signals.some(({ evidence }) => evidence === 'caller mutation')
    ).toBe(false);
    await client.inspect('safe-package', '2.0.0');
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    current = new Date(current.getTime() + 6 * 60 * 60 * 1000 + 1);
    await client.inspect('safe-package', '1.3.0');
    expect(fetchImplementation).toHaveBeenCalledTimes(3);
  });

  it('keeps unavailable publisher history unknown and never queries in offline mode', async () => {
    const fetchImplementation = vi.fn<typeof fetch>(async () =>
      packument({
        versions: {
          '1.0.0': { scripts: {} },
          '1.1.0': { scripts: {} },
          '1.2.0': { scripts: {} },
          '1.3.0': { scripts: {} },
          '2.0.0': { scripts: {} }
        }
      })
    );
    const client = new NpmPackageHealthClient({
      fetchImplementation,
      offline: true
    });

    const result = await client.inspect('safe-package', '1.3.0');

    expect(result.status).toBe('not_queried');
    expect(result.publisherHistoryStatus).toBe('unavailable');
    expect(result.publisherChangesObserved).toBeUndefined();
    expect(result.warnings).toContain('offline-cache-miss');
    expect(fetchImplementation).not.toHaveBeenCalled();

    const onlineClient = new NpmPackageHealthClient({
      fetchImplementation: async () =>
        packument({
          versions: {
            '1.0.0': { scripts: {} },
            '1.1.0': { scripts: {} },
            '1.2.0': { scripts: {} },
            '1.3.0': { scripts: {} },
            '2.0.0': { scripts: {} }
          }
        })
    });
    const observed = await onlineClient.inspect('safe-package', '1.3.0');
    expect(observed.status).toBe('available');
    expect(observed.publisherHistoryStatus).toBe('unavailable');
    expect(observed.publisherChangesObserved).toBeUndefined();
  });

  it('rejects impossible registry dates and mismatched package-version history', async () => {
    const invalidDate = new NpmPackageHealthClient({
      fetchImplementation: async () =>
        packument({
          time: {
            created: '2024-01-01T00:00:00.000Z',
            modified: '2026-11-06T12:00:00.000Z',
            '1.0.0': '2026-02-31T12:00:00.000Z'
          }
        }),
      now: () => new Date('2026-11-06T12:00:00.000Z')
    });
    const badDate = await invalidDate.inspect('safe-package', '1.0.0');
    expect(badDate.status).toBe('unavailable');
    expect(badDate.warnings).toContain('registry-packument-invalid');

    const source = await packument();
    const metadata = (await source.json()) as Record<string, unknown>;
    const versions = metadata.versions as Record<
      string,
      Record<string, unknown>
    >;
    versions['1.3.0'] = { ...versions['1.3.0'], version: '9.9.9' };
    const mismatched = new NpmPackageHealthClient({
      fetchImplementation: async () =>
        new Response(JSON.stringify(metadata), { status: 200 }),
      now: () => new Date('2026-11-06T12:00:00.000Z')
    });
    const identityMismatch = await mismatched.inspect('safe-package', '1.3.0');
    expect(identityMismatch.status).toBe('unavailable');
    expect(identityMismatch.warnings).toContain('registry-packument-invalid');
  });

  it('bounds parallel requests, deduplicates provider work and preserves install paths', async () => {
    let active = 0;
    let peak = 0;
    const fetchImplementation = vi.fn<typeof fetch>(async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 2));
      active--;
      return packument();
    });
    const client = new NpmPackageHealthClient({
      fetchImplementation,
      concurrency: 2,
      now: () => new Date('2026-11-06T12:00:00.000Z')
    });
    const input: NpmPackageIdentity[] = [
      {
        name: 'safe-package',
        version: '1.3.0',
        installPath: 'node_modules/a',
        registry: 'https://registry.npmjs.org'
      },
      {
        name: 'safe-package',
        version: '1.3.0',
        installPath: 'node_modules/b',
        registry: 'https://registry.npmjs.org'
      },
      {
        name: 'safe-package',
        version: '2.0.0',
        installPath: 'node_modules/c',
        registry: 'https://registry.npmjs.org'
      },
      {
        name: 'safe-package',
        version: '1.3.0',
        installPath: 'node_modules/d',
        registry: 'https://registry.npmjs.org'
      }
    ];

    const results = await client.inspectMany(input);

    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect(peak).toBeLessThanOrEqual(2);
    expect(results.map(({ installPath }) => installPath)).toEqual(
      input.map(({ installPath }) => installPath)
    );
    expect(results.map(({ health }) => health.installedVersion)).toEqual([
      '1.3.0',
      '1.3.0',
      '2.0.0',
      '1.3.0'
    ]);
  });

  it('reports a timed out provider as unavailable and retries only within bounds', async () => {
    const fetchImplementation = vi.fn<typeof fetch>(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            const error = new Error('aborted');
            error.name = 'AbortError';
            reject(error);
          });
        })
    );
    const client = new NpmPackageHealthClient({
      fetchImplementation,
      requestTimeoutMs: 5,
      random: () => 0
    });

    const result = await client.inspect('safe-package', '1.2.0');

    expect(result.status).toBe('unavailable');
    expect(result.warnings).toContain('registry-request-timeout');
    expect(fetchImplementation).toHaveBeenCalledTimes(3);
  });

  it('does not retry permanent registry client errors', async () => {
    const fetchImplementation = vi.fn<typeof fetch>(
      async () => new Response('not found', { status: 404 })
    );
    const client = new NpmPackageHealthClient({ fetchImplementation });

    const result = await client.inspect('safe-package', '1.2.0');

    expect(result.status).toBe('unavailable');
    expect(result.warnings).toContain('registry-http-404');
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
  });

  it('rejects oversized resolved inventory batches before provider work', async () => {
    const fetchImplementation = vi.fn<typeof fetch>();
    const client = new NpmPackageHealthClient({ fetchImplementation });
    const input = Array.from({ length: 1001 }, (_, index) => ({
      name: 'safe-package',
      version: '1.0.0',
      installPath: `node_modules/pkg-${index}`
    }));

    await expect(client.inspectMany(input)).rejects.toThrow(
      'package-health-batch-limit-exceeded'
    );
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('does not send lockfile identities from custom or unknown registries to npmjs', async () => {
    const fetchImplementation = vi.fn<typeof fetch>(async () => packument());
    const client = new NpmPackageHealthClient({ fetchImplementation });
    const results = await client.inspectMany([
      {
        name: 'safe-package',
        version: '1.3.0',
        installPath: 'node_modules/public/safe-package',
        registry: 'https://registry.npmjs.org'
      },
      {
        name: 'safe-package',
        version: '1.3.0',
        installPath: 'node_modules/private/safe-package',
        registry: 'https://packages.corp.example'
      },
      {
        name: 'unresolved-origin',
        version: '2.0.0',
        installPath: 'node_modules/unresolved-origin'
      }
    ]);

    expect(fetchImplementation).toHaveBeenCalledTimes(1);
    expect(results.map(({ health }) => health.status)).toEqual([
      'available',
      'not_queried',
      'not_queried'
    ]);
    expect(results.slice(1).map(({ health }) => health.warnings[0])).toEqual([
      'registry-identity-not-public-npm',
      'registry-identity-not-public-npm'
    ]);
  });
});
