import { describe, expect, it } from 'vitest';
import type { DistributionManifest } from '../../src/core/distribution/manifest.js';
import { renderHomebrewCandidate } from '../../src/core/distribution/homebrew.js';

const targets = [
  'darwin-arm64',
  'darwin-x64',
  'linux-arm64-gnu',
  'linux-x64-gnu'
] as const;

function signedManifest(): DistributionManifest {
  return {
    schema: 'toolip.dev/distribution/v1',
    repository: 'wbizmo/toolip',
    version: '3.2.1',
    sourceGitSha: 'a'.repeat(40),
    artifactKind: 'standalone-runtime-bundle',
    assets: targets.map((target, index) => ({
      target,
      filename: `toolip-3.2.1-${target}.tar.gz`,
      sha256: String(index + 1).repeat(64),
      size: 4096
    }))
  };
}

describe('operator-reviewed Homebrew formula candidate', () => {
  it('binds four target archives to exact signed digests without tap publication', () => {
    const candidate = renderHomebrewCandidate(signedManifest());
    expect(candidate.status).toBe('operator-review-required');
    expect(candidate.published).toBe(false);
    expect(candidate.tapRepository).toBe('wbizmo/homebrew-tap');
    expect(candidate.formula).toContain('class Toolip < Formula');
    expect(candidate.formula).toContain('on_macos do');
    expect(candidate.formula).toContain('on_linux do');
    expect(candidate.formula).toContain(
      'https://github.com/wbizmo/toolip/releases/download/v3.2.1/'
    );
    expect(candidate.formula).toContain('sha256 "1'.concat('1'.repeat(63), '"'));
    expect(candidate.formula).not.toContain('curl | sh');
  });

  it('rejects missing platforms, incorrect filenames and ambiguous release labels', () => {
    const signed = signedManifest();
    expect(() => renderHomebrewCandidate({
      ...signed, assets: signed.assets.slice(0, 3)
    })).toThrow('four explicit');
    expect(() => renderHomebrewCandidate({
      ...signed,
      assets: signed.assets.map((asset, index) => index === 0
        ? { ...asset, filename: 'toolip-latest.tar.gz' }
        : asset)
    })).toThrow('release contract');
    expect(() => renderHomebrewCandidate({
      ...signed, version: '3.2.1-rc1'
    })).toThrow('exact released');
  });
});
