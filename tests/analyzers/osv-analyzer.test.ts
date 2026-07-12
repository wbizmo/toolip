import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { OsvVulnerabilityAnalyzer } from '../../src/analyzers/vulnerability/osv-analyzer.js';
import { OsvClient } from '../../src/providers/osv/client.js';
import { MemoryCache } from '../../src/storage/memory-cache.js';

describe('OsvVulnerabilityAnalyzer', () => {
  it('creates normalized findings', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-'));
    try {
      await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'fixture', version: '1.0.0' },
          'node_modules/example-package': { version: '1.0.0' }
        }
      }));

      const client = new OsvClient({
        fetchImplementation: async () => new Response(JSON.stringify({
          results: [{ vulns: [{
            id: 'GHSA-test-0001',
            summary: 'Test vulnerability',
            database_specific: { severity: 'HIGH' },
            affected: [{ ranges: [{ events: [{ fixed: '1.0.1' }] }] }]
          }] }]
        }), { status: 200 })
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root,
        cache: new MemoryCache()
      });

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.severity).toBe('high');
      expect(result.findings[0]?.remediation?.fixedVersion).toBe('1.0.1');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
