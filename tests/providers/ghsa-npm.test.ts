import { describe, expect, it, vi } from 'vitest';
import {
  lookupGhsaNpmPackage
} from '../../src/providers/advisories/ghsa-npm.js';

const advisory = {
  ghsa_id: 'GHSA-2cf3-2cf3-2cf3',
  cve_id: 'CVE-2026-12345',
  type: 'reviewed',
  severity: 'high',
  published_at: '2026-01-01T00:00:00Z',
  vulnerabilities: [{
    package: { ecosystem: 'npm', name: '@public/example' },
    vulnerable_version_range: '< 2.0.0'
  }]
};
const json = (value: unknown) =>
  new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });

describe('exact npm GHSA provider claims', () => {
  it('never sends private package identity when consent is absent or offline is selected', async () => {
    const fetcher = vi.fn(async () => json([advisory]));
    for (const options of [
      { offline: true, allowPublicPackageLookup: true },
      { allowPublicPackageLookup: false }
    ]) {
      const result = await lookupGhsaNpmPackage(
        '@public/example', '1.2.3',
        { ...options, fetcher: fetcher as typeof fetch }
      );
      expect(result.status).toBe('offline');
      expect(result.noVulnerabilitiesProven).toBe(false);
      expect(result.advisories).toEqual([]);
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('evaluates strict npm ranges only against the exact named package and version', async () => {
    const fetcher = vi.fn(async (url: URL, init: RequestInit) => {
      expect(url.hostname).toBe('api.github.com');
      expect(url.pathname).toBe('/advisories');
      expect(url.searchParams.get('affects')).toBe('@public/example');
      expect(url.searchParams.get('ecosystem')).toBe('npm');
      expect(init.method).toBe('GET');
      expect(init.redirect).toBe('error');
      return json([advisory]);
    });
    const vulnerable = await lookupGhsaNpmPackage('@public/example', '1.2.3', {
      allowPublicPackageLookup: true,
      fetcher: fetcher as typeof fetch
    });
    expect(vulnerable.status).toBe('complete');
    expect(vulnerable.advisories).toHaveLength(1);
    expect(vulnerable.advisories[0]?.affected).toBe('yes');
    expect(vulnerable.advisories[0]?.aliases).toEqual(['CVE-2026-12345']);
    const newer = await lookupGhsaNpmPackage('@public/example', '2.1.0', {
      allowPublicPackageLookup: true,
      fetcher: fetcher as typeof fetch
    });
    expect(newer.advisories[0]?.affected).toBe('no');
    expect(newer.noVulnerabilitiesProven).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it.each(['reviewed', 'unreviewed', 'malware'] as const)(
    'keeps %s advisory classifications distinct in GHSA evidence',
    async (kind) => {
      const fetcher = vi.fn(async (url: URL) => {
        expect(url.searchParams.get('type')).toBe(kind);
        return json([{ ...advisory, type: kind }]);
      });
      const result = await lookupGhsaNpmPackage('@public/example', '1.2.3', {
        advisoryType: kind,
        allowPublicPackageLookup: true,
        fetcher: fetcher as typeof fetch
      });
      expect(result.advisoryType).toBe(kind);
      expect(result.advisories[0]?.advisoryType).toBe(kind);
      expect(result.advisories[0]?.reviewed).toBe(kind === 'reviewed');
      expect(result.status).toBe('complete');
    }
  );

  it('refuses to silently declare malformed provider ranges safe', async () => {
    const fetcher = vi.fn(async () => json([{
      ...advisory,
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: '@public/example' },
        vulnerable_version_range: 'malformed range <script>'
      }]
    }]));
    const result = await lookupGhsaNpmPackage('@public/example', '1.0.0', {
      allowPublicPackageLookup: true,
      fetcher: fetcher as typeof fetch
    });
    expect(result.status).toBe('partial');
    expect(result.advisories[0]?.affected).toBe('unknown');
    expect(result.noVulnerabilitiesProven).toBe(false);
  });

  it('treats a full first response page as incomplete instead of claiming exhaustive coverage', async () => {
    const list = Array.from({ length: 100 }, () => advisory);
    const result = await lookupGhsaNpmPackage('@public/example', '1.0.0', {
      allowPublicPackageLookup: true,
      fetcher: vi.fn(async () => json(list)) as typeof fetch
    });
    expect(result.status).toBe('partial');
    expect(result.advisories).toHaveLength(1);
    expect(result.reasons.join(' ')).toMatch(/more advisories may exist/i);
  });

  it('reports request failure as failed without echoing supplied names or credentials', async () => {
    const result = await lookupGhsaNpmPackage('@public/example', '1.0.0', {
      allowPublicPackageLookup: true,
      fetcher: vi.fn(async () =>
        new Response('unavailable', { status: 429 })
      ) as typeof fetch
    });
    expect(result.status).toBe('failed');
    expect(result.advisories).toEqual([]);
  });

  it('rejects exact-version impostors, URL injection and invalid names before network access', async () => {
    const fetcher = vi.fn(async () => json([]));
    for (const [name, version] of [
      ['@private/example?token=x', '1.2.3'],
      ['@public/example', '^1.2.3'],
      ['@public/example', 'v1.2.3'],
      ['@public/example', '1.2.3\nhttps://evil.invalid']
    ]) {
      await expect(lookupGhsaNpmPackage(name, version, {
        allowPublicPackageLookup: true,
        fetcher: fetcher as typeof fetch
      })).rejects.toThrow();
    }
    expect(fetcher).not.toHaveBeenCalled();
  });
});
