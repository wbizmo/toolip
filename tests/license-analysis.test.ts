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
      dependencies: { safe: '^1.0.0', restrictive: '^2.0.0', unavailable: '^3.0.0' }
    })
  );
  await writeFile(
    path.join(root, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: { safe: '^1.0.0', restrictive: '^2.0.0', unavailable: '^3.0.0' }
        },
        'node_modules/safe': { name: 'safe', version: '1.2.3' },
        'node_modules/restrictive': { name: 'restrictive', version: '2.4.0' },
        'node_modules/unavailable': { name: 'unavailable', version: '3.1.0' }
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
        async getVersion(name: string, version: string): Promise<DepsDevVersionResponse> {
          requested.push(`${name}@${version}`);
          if (name === 'unavailable') {
            throw new Error('offline');
          }
          return { licenses: name === 'restrictive' ? ['GPL-3.0-only'] : ['MIT'] };
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
      expect(result.findings.some((finding) =>
        finding.ruleId === 'TOOLIP-LICENSE-RESTRICTIVE'
      )).toBe(true);
      expect(result.findings.some((finding) =>
        finding.ruleId === 'TOOLIP-LICENSE-METADATA-UNAVAILABLE'
      )).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not invent a license when deps.dev reports none', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-license-empty-'));

    try {
      await writeFile(path.join(root, 'package.json'), JSON.stringify({ dependencies: { mystery: '^1.0.0' } }));
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { mystery: '^1.0.0' } },
            'node_modules/mystery': { name: 'mystery', version: '1.0.7' }
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
});
