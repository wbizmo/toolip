import { describe, expect, it, vi } from 'vitest';
import { createProgram } from '../../src/cli/program.js';
import { explainScanEgress } from '../../src/core/privacy-egress.js';

describe('declared scan egress manifest', () => {
  it('describes baseline network and inactive opt-in providers distinctly', () => {
    const manifest = explainScanEgress();
    expect(manifest.systemEgressVerified).toBe(false);
    expect(manifest.coverage).toBe('declared-surfaces-only');
    expect(manifest.installNetworkSeparate).toBe(true);
    expect(manifest.surfaces.find((item) => item.capability === 'osv-advisories')?.status)
      .toBe('possible');
    expect(manifest.surfaces.find((item) => item.capability === 'license-metadata')?.status)
      .toBe('disabled');
  });

  it('does not claim network independence or hide disabled providers for offline scans', () => {
    const manifest = explainScanEgress({
      offline: true,
      licenses: true,
      packageHealth: true,
      npmProvenancePolicy: true,
      allowGoToolExecution: true
    });
    expect(manifest.offlineRequested).toBe(true);
    expect(manifest.systemEgressVerified).toBe(false);
    expect(manifest.surfaces.every((item) => item.status === 'disabled')).toBe(true);
    expect(manifest.caveats).toEqual(
      expect.arrayContaining([
        expect.stringContaining('not a measured egress audit')
      ])
    );
  });

  it('shows opt-in provider destinations without exposing any source content', () => {
    const manifest = explainScanEgress({
      licenses: true,
      packageHealth: true,
      allowPublicScope: true
    });
    expect(manifest.surfaces.find((item) => item.capability === 'license-metadata'))
      .toMatchObject({
        status: 'opt-in',
        destination: 'https://api.deps.dev/v3'
      });
    expect(manifest.surfaces.find((item) => item.capability === 'package-health')?.status)
      .toBe('opt-in');
    expect(JSON.stringify(manifest)).not.toContain('private/project');
  });

  it('exposes the manifest without loading a scanner or initiating a provider query', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      await createProgram().parseAsync([
        'node',
        'toolip',
        'privacy',
        'explain',
        '--offline'
      ]);
      const manifest = JSON.parse(String(log.mock.lastCall?.[0]));
      expect(manifest.command).toBe('scan');
      expect(manifest.offlineRequested).toBe(true);
      expect(manifest.systemEgressVerified).toBe(false);
    } finally {
      log.mockRestore();
    }
  });
});
