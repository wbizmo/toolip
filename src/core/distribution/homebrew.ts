import type { DistributionManifest } from './manifest.js';

export type HomebrewCandidate = Readonly<{
  schema: 'toolip.dev/homebrew-candidate/v1';
  status: 'operator-review-required';
  published: false;
  sourceGitSha: string;
  tapRepository: 'wbizmo/homebrew-tap';
  formula: string;
}>;

const supported = [
  'darwin-arm64',
  'darwin-x64',
  'linux-arm64-gnu',
  'linux-x64-gnu'
] as const;

/**
 * Render only a REVIEW CANDIDATE from an already Ed25519-verified immutable
 * distribution manifest. Never auto-push to the external Homebrew tap.
 *
 * All four platforms must have archives; unvalidated runtime layout, actual
 * archive availability, provenance and release approval remain separate.
 */
export function renderHomebrewCandidate(
  manifest: DistributionManifest
): HomebrewCandidate {
  if (manifest.schema !== 'toolip.dev/distribution/v1' ||
      manifest.repository !== 'wbizmo/toolip' ||
      manifest.artifactKind !== 'standalone-runtime-bundle' ||
      !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(manifest.version) ||
      !/^[a-f0-9]{40}$/u.test(manifest.sourceGitSha))
    throw new TypeError('Homebrew candidate requires an exact released source identity.');
  const selected = new Map(manifest.assets.map((item) => [item.target, item]));
  if (selected.size !== manifest.assets.length ||
      supported.some((target) => !selected.has(target)))
    throw new Error('Homebrew candidate requires all four explicit signed platform archives.');

  for (const target of supported) {
    const item = selected.get(target);
    if (!item || !/^[a-f0-9]{64}$/u.test(item.sha256) ||
        item.filename !== `toolip-${manifest.version}-${target}.tar.gz`)
      throw new Error('Homebrew asset name or digest differs from the expected release contract.');
  }
  const url = (target: typeof supported[number]): string =>
    `https://github.com/wbizmo/toolip/releases/download/v${manifest.version}/${selected.get(target)?.filename}`;
  const sum = (target: typeof supported[number]): string =>
    selected.get(target)?.sha256 as string;

  const formula = `# Generated candidate only; do not push or publish before owner
# approval, archive layout checks, provenance and clean macOS/Linux testing.
# Manifest source: wbizmo/toolip@${manifest.sourceGitSha}
class Toolip < Formula
  desc "Local-first developer security analysis CLI"
  homepage "https://www.zivoralabs.xyz/open-source/toolip/"
  version "${manifest.version}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "${url('darwin-arm64')}"
      sha256 "${sum('darwin-arm64')}"
    else
      url "${url('darwin-x64')}"
      sha256 "${sum('darwin-x64')}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "${url('linux-arm64-gnu')}"
      sha256 "${sum('linux-arm64-gnu')}"
    else
      url "${url('linux-x64-gnu')}"
      sha256 "${sum('linux-x64-gnu')}"
    end
  end

  def install
    bin.install "toolip"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/toolip --version")
  end
end
`;
  return Object.freeze({
    schema: 'toolip.dev/homebrew-candidate/v1',
    status: 'operator-review-required',
    published: false,
    sourceGitSha: manifest.sourceGitSha,
    tapRepository: 'wbizmo/homebrew-tap',
    formula
  });
}
