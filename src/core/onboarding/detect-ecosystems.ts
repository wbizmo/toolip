import { walkProjectFiles } from '../file-walker.js';

type Ecosystem = 'javascript' | 'python' | 'go' | 'rust' | 'java' | 'php';
type Confidence = 'lockfile-candidate' | 'manifest-only';
type Discovery = Readonly<{
  ecosystem: Ecosystem;
  confidence: Confidence;
  manifestCount: number;
  lockfileCount: number;
  examples: readonly string[];
  caveat: string;
}>;

export type OnboardingDiscovery = Readonly<{
  schema: 'toolip.dev/onboarding/v1';
  status: 'requires-scan';
  projectFilesDiscovered: number;
  detected: readonly Discovery[];
  firstScanCommand: 'toolip scan --offline --fail-on-incomplete';
  networkOnFirstScan: false;
  installationMayUseNetwork: true;
  scriptsExecutedByDetection: false;
  completeSecurityScanPerformed: false;
  limitations: readonly string[];
}>;

const catalog: ReadonlyArray<Readonly<{
  name: Ecosystem;
  manifests: RegExp;
  locks: RegExp;
  caveat: string;
}>> = [
  {
    name: 'javascript',
    manifests: /(?:^|\/)package\.json$/iu,
    locks: /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/iu,
    caveat: 'Installed dependency identity requires successful parsing of an exact supported lockfile.'
  },
  {
    name: 'python',
    manifests: /(?:^|\/)(?:pyproject\.toml|Pipfile|setup\.(?:py|cfg)|requirements(?:-[^/]+)?\.(?:txt|in))$/iu,
    locks: /(?:^|\/)(?:uv\.lock|poetry\.lock|Pipfile\.lock|[^/]*requirements[^/]*\.txt)$/iu,
    caveat: 'Target markers, extras and non-exact requirements may remain unknown without an explicit profile.'
  },
  {
    name: 'go',
    manifests: /(?:^|\/)go\.(?:mod|work)$/iu,
    locks: /(?:^|\/)(?:go\.sum|vendor\/modules\.txt)$/iu,
    caveat: 'go.sum validates module hashes but does not alone prove the active resolved graph.'
  },
  {
    name: 'rust',
    manifests: /(?:^|\/)Cargo\.toml$/u,
    locks: /(?:^|\/)Cargo\.lock$/u,
    caveat: 'Cargo target features, git/path packages and registry artifact provenance may remain unverified.'
  },
  {
    name: 'java',
    manifests: /(?:^|\/)(?:pom\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?)$/u,
    locks: /(?:^|\/)(?:maven-dependency-tree\.(?:json|txt)|gradle-dependencies\.json|gradle\.lockfile)$/u,
    caveat: 'Versioned Maven/Gradle exports must bind to the scanned revision before the graph is trusted.'
  },
  {
    name: 'php',
    manifests: /(?:^|\/)composer\.json$/iu,
    locks: /(?:^|\/)composer\.lock$/iu,
    caveat: 'Composer path repositories, aliases and ambiguous package identities may remain unresolved.'
  }
];
const maximumExamplePaths = 4;

/** Read-only, bounded discovery. Paths are never opened or executed here. */
export async function discoverOnboardingEcosystems(
  root: string
): Promise<OnboardingDiscovery> {
  const files = await walkProjectFiles(root);
  const paths = files.map((file) => file.relativePath).sort();
  const detected: Discovery[] = [];

  for (const item of catalog) {
    const manifests = paths.filter((file) => item.manifests.test(file));
    const locks = paths.filter((file) => item.locks.test(file));
    if (manifests.length === 0 && locks.length === 0) continue;
    detected.push({
      ecosystem: item.name,
      confidence: locks.length ? 'lockfile-candidate' : 'manifest-only',
      manifestCount: manifests.length,
      lockfileCount: locks.length,
      examples: Object.freeze(
        [...new Set([...manifests, ...locks])]
          .sort()
          .slice(0, maximumExamplePaths)
      ),
      caveat: item.caveat
    });
  }

  return Object.freeze({
    schema: 'toolip.dev/onboarding/v1',
    status: 'requires-scan',
    projectFilesDiscovered: files.length,
    detected: Object.freeze(detected),
    firstScanCommand: 'toolip scan --offline --fail-on-incomplete',
    networkOnFirstScan: false,
    installationMayUseNetwork: true,
    scriptsExecutedByDetection: false,
    completeSecurityScanPerformed: false,
    limitations: Object.freeze([
      'Detected filenames are candidates, not validated dependency versions or package counts.',
      'A source scan may have incomplete coverage without usable lockfile graphs or advisory data.',
      'npx/npm installation may access the network before a local Toolip scan begins.',
      'Toolip never installs project dependencies or runs project build scripts merely to detect ecosystems.'
    ])
  });
}
