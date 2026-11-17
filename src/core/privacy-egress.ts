/**
 * Declared scan egress surfaces. This is explanatory metadata only, not proof
 * that every code path has been captured or that an operating-system network
 * sandbox has been installed. Issue #109 requires independent egress tests.
 */
export type EgressStatus = 'disabled' | 'possible' | 'opt-in';

export type EgressSurface = Readonly<{
  capability: string;
  status: EgressStatus;
  destination: string;
  dataCategories: readonly string[];
  consent: string;
}>;

export type ScanEgressManifest = Readonly<{
  schema: 'toolip.dev/egress-manifest/v1';
  command: 'scan' | 'advisories-npm';
  offlineRequested: boolean;
  systemEgressVerified: false;
  coverage: 'declared-surfaces-only';
  installNetworkSeparate: true;
  surfaces: readonly EgressSurface[];
  caveats: readonly string[];
}>;

export function explainScanEgress(
  options: Readonly<{
    offline?: boolean;
    licenses?: boolean;
    packageHealth?: boolean;
    allowGoToolExecution?: boolean;
    npmProvenancePolicy?: boolean;
    allowPublicScope?: boolean;
    allowPublicCveLookup?: boolean;
  }> = {}
): ScanEgressManifest {
  const offline = options.offline === true;
  const surface = (
    capability: string,
    mode: 'baseline' | 'opt-in',
    enabled: boolean,
    destination: string,
    dataCategories: readonly string[],
    consent: string
  ): EgressSurface => ({
    capability,
    status: offline
      ? 'disabled'
      : mode === 'baseline'
        ? 'possible'
        : enabled
          ? 'opt-in'
          : 'disabled',
    destination,
    dataCategories,
    consent
  });

  const surfaces: EgressSurface[] = [
    surface(
      'osv-advisories',
      'baseline',
      true,
      'https://api.osv.dev/v1/querybatch',
      ['public ecosystem', 'exact package name', 'exact installed version'],
      'Baseline online vulnerability lookup; use --offline to request zero registry/advisory egress.'
    ),
    surface(
      'exploit-intelligence',
      'baseline',
      true,
      'https://api.first.org/data/v1/epss and https://www.cisa.gov',
      ['public CVE identifiers'],
      'Conditional public EPSS/CISA KEV enrichment in online mode.'
    ),
    surface(
      'public-cve-enrichment',
      'opt-in',
      options.allowPublicCveLookup === true,
      'https://api.github.com/advisories and https://services.nvd.nist.gov/rest/json/cves/2.0',
      ['public CVE identifier'],
      'Requires explicit --enrich-cve and --allow-public-cve-lookup in the scan command.'
    ),
    surface(
      'license-metadata',
      'opt-in',
      options.licenses === true,
      'https://api.deps.dev/v3',
      ['exact public package identity', 'version'],
      'Requires --licenses; private and scoped identity rules remain in force.'
    ),
    surface(
      'package-health',
      'opt-in',
      options.packageHealth === true,
      'https://registry.npmjs.org',
      ['public npm package name', 'version'],
      'Requires --package-health; private namespace disclosure needs explicit consent.'
    ),
    surface(
      'npm-provenance',
      'opt-in',
      options.npmProvenancePolicy === true,
      'https://registry.npmjs.org',
      ['trusted public npm package identity', 'artifact integrity metadata'],
      'Requires --npm-provenance-policy outside the scanned project.'
    ),
    surface(
      'go-module-resolution',
      'opt-in',
      options.allowGoToolExecution === true,
      'https://proxy.golang.org and https://sum.golang.org',
      ['Go module path', 'resolved module version'],
      'Requires --allow-go-tool-execution and may invoke the external Go toolchain.'
    )
  ];

  return Object.freeze({
    schema: 'toolip.dev/egress-manifest/v1',
    command: 'scan',
    offlineRequested: offline,
    systemEgressVerified: false,
    coverage: 'declared-surfaces-only',
    installNetworkSeparate: true,
    surfaces: Object.freeze(surfaces),
    caveats: Object.freeze([
      'This manifest declares known provider surfaces and is not a measured egress audit.',
      'npm/npx installation or update traffic is separate from the Toolip scan process.',
      'Custom plugins, external tools, proxy settings and future providers need separate review.',
      options.allowPublicScope === true
        ? 'Public scoped npm package-name disclosure was explicitly requested.'
        : 'Public scoped npm package-name disclosure was not explicitly requested.'
    ])
  });
}

/**
 * The package-name query is a distinct manual command from `scan`; it
 * requires per-invocation consent. Showing this disclosure never makes an
 * advisory HTTP request or reads a local project manifest.
 */
export function explainNpmAdvisoryEgress(
  options: { offline?: boolean; allowPublicPackageLookup?: boolean } = {}
): ScanEgressManifest {
  const online = !options.offline && options.allowPublicPackageLookup === true;
  return Object.freeze({
    schema: 'toolip.dev/egress-manifest/v1',
    command: 'advisories-npm',
    offlineRequested: options.offline === true,
    systemEgressVerified: false,
    coverage: 'declared-surfaces-only',
    installNetworkSeparate: true,
    surfaces: Object.freeze([
      Object.freeze({
        capability: 'ghsa-exact-npm-instance',
        status: online ? 'opt-in' as const : 'disabled' as const,
        destination: 'https://api.github.com/advisories',
        dataCategories: Object.freeze([
          'exact explicitly supplied public npm package name',
          'npm ecosystem identifier'
        ]),
        consent: 'Requires advisories npm <name> <version> --allow-public-package-lookup without --offline.'
      })
    ]),
    caveats: Object.freeze([
      'The package name is disclosed in a query parameter when the operator explicitly opts in.',
      'The exact local installed version is evaluated after the response and is not included in the GHSA request.',
      'A single first page is not exhaustive; unsupported ranges and incomplete responses remain unknown.',
      'npm/npx installation traffic is separate from Toolip advisory query traffic.',
      'This manifest is not an operating-system-level egress guarantee.'
    ])
  });
}
