import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { inspectProjectPackageHealth } from '../../src/commands/package-health.js';

const roots: string[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function fixture(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-package-health-'));
  roots.push(root);
  return root;
}

describe('project package-health command integration', () => {
  it('joins public metadata to exact lockfile instances and protects scoped names', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': { name: 'fixture', version: '1.0.0' },
          'node_modules/@private/pkg': { version: '1.0.0' },
          'node_modules/parent/node_modules/@private/pkg': { version: '2.0.0' }
        }
      })
    );
    const fetch = vi.fn<typeof globalThis.fetch>();
    vi.stubGlobal('fetch', fetch);

    const results = await inspectProjectPackageHealth(root);

    expect(results).toHaveLength(2);
    expect(
      results.map(({ version, installPath }) => [version, installPath])
    ).toEqual([
      ['1.0.0', 'node_modules/@private/pkg'],
      ['2.0.0', 'node_modules/parent/node_modules/@private/pkg']
    ]);
    expect(results.map(({ status }) => status)).toEqual([
      'not_queried',
      'not_queried'
    ]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('only sends scoped project identities after explicit public-scope opt-in', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/@public/pkg': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/@public/pkg/-/pkg-1.0.0.tgz'
          }
        }
      })
    );
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () => new Response('not found', { status: 404 })
    );
    vi.stubGlobal('fetch', fetch);

    const results = await inspectProjectPackageHealth(root, {
      allowPublicScope: true
    });

    expect(results).toHaveLength(1);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(String(fetch.mock.calls[0]?.[0])).toContain(
      'https://registry.npmjs.org/%40public%2Fpkg'
    );
  });

  it('preserves exact lock origin and integrity without querying custom registries', async () => {
    const root = await fixture();
    const integrity = `sha512-${Buffer.from('fixture-integrity').toString('base64')}`;
    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/public-pkg': {
            version: '1.2.3',
            resolved:
              'https://packages.example.test/npm/public-pkg/-/public-pkg-1.2.3.tgz?token=must-not-appear',
            integrity
          }
        }
      })
    );
    const fetch = vi.fn<typeof globalThis.fetch>();
    vi.stubGlobal('fetch', fetch);

    const [result] = await inspectProjectPackageHealth(root);
    expect(result).toMatchObject({
      package: 'public-pkg',
      version: '1.2.3',
      resolutionConfidence: 'lockfile',
      registryOrigin: 'https://packages.example.test',
      resolvedArtifact:
        'https://packages.example.test/npm/public-pkg/-/public-pkg-1.2.3.tgz',
      lockIntegrity: integrity,
      status: 'not_queried'
    });
    expect(JSON.stringify(result)).not.toContain('must-not-appear');
    expect(fetch).not.toHaveBeenCalled();
  });
});
