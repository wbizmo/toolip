import { describe, expect, it, vi } from 'vitest';
import { createProgram } from '../../src/cli/program.js';
import { explainScanEgress, explainNpmAdvisoryEgress } from '../../src/core/privacy-egress.js';

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

  it('describes the separate GHSA query consent without implying a complete privacy audit', () => {
    const disabled = explainNpmAdvisoryEgress({ offline: true });
    expect(disabled.command).toBe('advisories-npm');
    expect(disabled.surfaces[0]?.status).toBe('disabled');
    expect(disabled.systemEgressVerified).toBe(false);

    const consented = explainNpmAdvisoryEgress({
      allowPublicPackageLookup: true
    });
    expect(consented.surfaces[0]?.status).toBe('opt-in');
    expect(consented.surfaces[0]?.destination)
      .toBe('https://api.github.com/advisories');
    expect(JSON.stringify(consented)).not.toContain('private/repository');
  });

  it('can print advisory-only disclosure without making a network request', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      await createProgram().parseAsync([
        'node', 'toolip', 'privacy', 'explain',
        '--command', 'advisories-npm', '--allow-public-package-lookup'
      ]);
      const explanation = JSON.parse(String(spy.mock.lastCall?.[0]));
      expect(explanation.command).toBe('advisories-npm');
      expect(explanation.surfaces[0].status).toBe('opt-in');
      expect(explanation.systemEgressVerified).toBe(false);
    } finally {
      spy.mockRestore();
    }
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
