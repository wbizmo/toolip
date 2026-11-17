import { describe, expect, it, vi } from 'vitest';
import { enrichCve } from '../../src/providers/advisories/multi-source.js';

const cve = 'CVE-2026-12345';
const ghsa = [{
  ghsa_id: 'GHSA-2cf3-2cf3-2cf3',
  cve_id: cve,
  type: 'reviewed',
  severity: 'high',
  published_at: '2026-01-01T00:00:00Z',
  vulnerabilities: [{
    package: { ecosystem: 'npm', name: 'package' },
    vulnerable_version_range: '<1.0.0'
  }]
}];
const nvd = { vulnerabilities: [{
  cve: {
    id: cve,
    published: '2026-01-01T00:00:00Z',
    metrics: {
      cvssMetricV31: [{
        cvssData: { baseScore: 8.2, baseSeverity: 'HIGH' }
      }]
    },
    weaknesses: [{
      description: [{ lang: 'en', value: 'CWE-79' }]
    }]
  }
}] };

describe('CVE enrichment source and consent boundaries', () => {
  it('never calls providers in offline or non-consented mode', async () => {
    const fetcher = vi.fn(async () => new Response('[]'));
    const result = await enrichCve(cve, { fetcher: fetcher as typeof fetch });
    expect(result.status).toBe('offline');
    expect(result.claims).toHaveLength(0);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('preserves conflicting GHSA/NVD claims rather than treating them as separate installed vulnerabilities', async () => {
    const fetcher = vi.fn(async (url: URL | string | Request) => {
      const body = String(url).includes('api.github.com') ? ghsa : nvd;
      return new Response(JSON.stringify(body), { status: 200 });
    });
    const result = await enrichCve(cve, {
      allowPublicCveLookup: true,
      fetcher: fetcher as typeof fetch
    });
    expect(result.status).toBe('complete');
    expect(result.claims).toHaveLength(2);
    expect(result.claims.map((x) => x.source).sort()).toEqual(['ghsa', 'nvd']);
    expect(result.claims.every((item) => item.cpeIsPackageEvidence === false)).toBe(true);
    expect(result.claims.find((x) => x.source === 'nvd')?.cvssScore).toBe(8.2);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('marks provider failure partial, retaining independently supported claims', async () => {
    const fetcher = vi.fn(async (url: URL | string | Request) => {
      if (String(url).includes('nvd.nist.gov'))
        return new Response('provider failed', { status: 503 });
      return new Response(JSON.stringify(ghsa), { status: 200 });
    });
    const result = await enrichCve(cve, {
      allowPublicCveLookup: true,
      fetcher: fetcher as typeof fetch
    });
    expect(result.status).toBe('partial');
    expect(result.claims).toHaveLength(1);
    expect(result.sourceStatus.nvd).toBe('failed');
  });

  it('rejects invalid and ambiguous CVE identities before egress', async () => {
    const fetcher = vi.fn(async () => new Response('[]'));
    await expect(enrichCve('CVE-2026-../../internal', {
      allowPublicCveLookup: true,
      fetcher: fetcher as typeof fetch
    })).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
});
