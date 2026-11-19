import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyzeLicenses } from '../src/core/license-analysis.js';
import type { DepsDevVersionResponse } from '../src/providers/depsdev/client.js';

async function writeFixture(root: string): Promise<void> {
  await writeFile(
    path.join(root, 'package.json'),
    JSON.stringify({
      dependencies: {
        safe: '^1.0.0',
        restrictive: '^2.0.0',
        unavailable: '^3.0.0'
      }
    })
  );
  await writeFile(
    path.join(root, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: {
            safe: '^1.0.0',
            restrictive: '^2.0.0',
            unavailable: '^3.0.0'
          }
        },
        'node_modules/safe': {
          name: 'safe',
          version: '1.2.3',
          resolved: 'https://registry.npmjs.org/safe/-/safe-1.2.3.tgz'
        },
        'node_modules/restrictive': {
          name: 'restrictive',
          version: '2.4.0',
          resolved:
            'https://registry.npmjs.org/restrictive/-/restrictive-2.4.0.tgz'
        },
        'node_modules/unavailable': {
          name: 'unavailable',
          version: '3.1.0',
          resolved:
            'https://registry.npmjs.org/unavailable/-/unavailable-3.1.0.tgz'
        }
      }
    })
  );
}

describe('analyzeLicenses', () => {
  it('uses lockfile-resolved versions and authoritative provider licenses', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-license-'));

    try {
      await writeFixture(root);
      const requested: string[] = [];
      const provider = {
        async getVersion(
          name: string,
          version: string
        ): Promise<DepsDevVersionResponse> {
          requested.push(`${name}@${version}`);
          if (name === 'unavailable') {
            throw new Error('offline');
          }
          return {
            licenses: name === 'restrictive' ? ['GPL-3.0-only'] : ['MIT']
          };
        }
      };

      const result = await analyzeLicenses(root, provider);

      expect(requested.sort()).toEqual([
        'restrictive@2.4.0',
        'safe@1.2.3',
        'unavailable@3.1.0'
      ]);
      expect(result.summary.total).toBe(3);
      expect(result.summary.restrictive).toBe(1);
      expect(result.summary.unknown).toBe(1);
      expect(result.summary.distribution.MIT).toBe(1);
      expect(result.warnings).toEqual([
        'License metadata unavailable for unavailable@3.1.0: offline'
      ]);
      expect(
        result.findings.some(
          (finding) => finding.ruleId === 'TOOLIP-LICENSE-RESTRICTIVE'
        )
      ).toBe(true);
      expect(
        result.findings.some(
          (finding) => finding.ruleId === 'TOOLIP-LICENSE-METADATA-UNAVAILABLE'
        )
      ).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not invent a license when deps.dev reports none', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-license-empty-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ dependencies: { mystery: '^1.0.0' } })
      );
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { mystery: '^1.0.0' } },
            'node_modules/mystery': {
              name: 'mystery',
              version: '1.0.7',
              resolved: 'https://registry.npmjs.org/mystery/-/mystery-1.0.7.tgz'
            }
          }
        })
      );

      const result = await analyzeLicenses(root, {
        async getVersion() {
          return { licenses: [] };
        }
      });

      expect(result.summary.unknown).toBe(1);
      expect(result.licenses[0]?.metadataSource).toBe('deps.dev');
      expect(result.findings[0]?.ruleId).toBe('TOOLIP-LICENSE-UNKNOWN');
      expect(result.warnings).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('bounds metadata concurrency and reports provider request metrics', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-license-budget-')
    );
    let active = 0;
    let peak = 0;
    try {
      await writeFixture(root);
      const result = await analyzeLicenses(
        root,
        {
          async getVersion() {
            active++;
            peak = Math.max(peak, active);
            await new Promise((resolve) => setTimeout(resolve, 5));
            active--;
            return { licenses: ['MIT'] };
          }
        },
        undefined,
        { concurrency: 1 }
      );
      expect(peak).toBe(1);
      expect(result.providerMetrics).toEqual({
        requests: 3,
        maxConcurrency: 1
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('orders multiple exact versions independently of lockfile entry order', async () => {
    const roots = await Promise.all([
      mkdtemp(path.join(os.tmpdir(), 'toolip-license-order-a-')),
      mkdtemp(path.join(os.tmpdir(), 'toolip-license-order-b-'))
    ]);
    const records = {
      'node_modules/safe-old': {
        name: 'safe',
        version: '1.0.0',
        resolved: 'https://registry.npmjs.org/safe/-/safe-1.0.0.tgz'
      },
      'node_modules/safe-new': {
        name: 'safe',
        version: '2.0.0',
        resolved: 'https://registry.npmjs.org/safe/-/safe-2.0.0.tgz'
      }
    };
    try {
      for (const [index, root] of roots.entries()) {
        await writeFile(
          path.join(root, 'package-lock.json'),
          JSON.stringify({
            lockfileVersion: 3,
            packages: {
              '': {
                dependencies: {
                  'safe-old': 'npm:safe@1.0.0',
                  'safe-new': 'npm:safe@2.0.0'
                }
              },
              ...(index === 0
                ? records
                : Object.fromEntries(Object.entries(records).reverse()))
            }
          })
        );
      }
      const analyze = (root: string) =>
        analyzeLicenses(root, {
          async getVersion(_name, version) {
            await new Promise((resolve) =>
              setTimeout(resolve, version === '1.0.0' ? 2 : 0)
            );
            return { licenses: [`license-${version}`] };
          }
        });
      const [first, second] = await Promise.all(roots.map(analyze));
      expect(
        first.licenses.map(({ version, license }) => [version, license])
      ).toEqual([
        ['1.0.0', 'license-1.0.0'],
        ['2.0.0', 'license-2.0.0']
      ]);
      expect(second.licenses).toEqual(first.licenses);
      expect(second.findings).toEqual(first.findings);
    } finally {
      await Promise.all(
        roots.map((root) => rm(root, { recursive: true, force: true }))
      );
    }
  });

  it('deduplicates exact instances, preserves production classification and withholds mixed origins', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-license-origin-')
    );
    let calls = 0;
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              dependencies: { 'z-runtime': 'npm:shared@1.0.0' },
              devDependencies: { 'a-test': 'npm:shared@1.0.0' }
            },
            'node_modules/a-test': {
              name: 'shared',
              version: '1.0.0',
              resolved: 'https://packages.corp.example/shared-1.0.0.tgz'
            },
            'node_modules/z-runtime': {
              name: 'shared',
              version: '1.0.0',
              resolved: 'https://registry.npmjs.org/shared/-/shared-1.0.0.tgz'
            }
          }
        })
      );

      const result = await analyzeLicenses(root, {
        async getVersion() {
          calls++;
          return { licenses: ['MIT'] };
        }
      });

      expect(result.licenses).toHaveLength(1);
      expect(result.licenses[0]).toMatchObject({
        name: 'shared',
        version: '1.0.0',
        type: 'dependency',
        license: 'UNKNOWN',
        metadataError: 'registry-origin-unverified'
      });
      expect(calls).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not start provider requests when already cancelled', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-license-cancel-')
    );
    const controller = new AbortController();
    controller.abort();
    let called = false;
    try {
      await writeFixture(root);
      const result = await analyzeLicenses(
        root,
        {
          async getVersion() {
            called = true;
            return { licenses: ['MIT'] };
          }
        },
        controller.signal
      );
      expect(called).toBe(false);
      expect(result.providerMetrics.requests).toBe(0);
      expect(result.summary.unknown).toBe(3);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('withholds scoped and unverified-origin package names without consent', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-license-privacy-')
    );
    let calls = 0;
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              dependencies: { '@private/library': '1.0.0', custom: '2.0.0' }
            },
            'node_modules/@private/library': {
              version: '1.0.0',
              resolved:
                'https://registry.npmjs.org/@private/library/-/library-1.0.0.tgz'
            },
            'node_modules/custom': { version: '2.0.0' }
          }
        })
      );
      const result = await analyzeLicenses(root, {
        async getVersion() {
          calls++;
          return { licenses: ['MIT'] };
        }
      });

      expect(calls).toBe(0);
      expect(result.licenses.map((entry) => entry.license)).toEqual([
        'UNKNOWN',
        'UNKNOWN'
      ]);
      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('scoped-name-not-queried'),
          expect.stringContaining('registry-origin-unverified')
        ])
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
