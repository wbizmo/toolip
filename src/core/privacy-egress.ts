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
  command: 'scan';
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
  }> = {}
): ScanEgressManifest {
  const offline = options.offline === true;
  const surface = (
    capability: string,
    active: boolean,
    destination: string,
    dataCategories: readonly string[],
    consent: string
  ): EgressSurface => ({
    capability,
    status: offline ? 'disabled' : active ? 'opt-in' : 'possible',
    destination,
    dataCategories,
    consent
  });

  const surfaces: EgressSurface[] = [
    surface(
      'osv-advisories',
      false,
      'https://api.osv.dev/v1/querybatch',
      ['public ecosystem', 'exact package name', 'exact installed version'],
      'Baseline online vulnerability lookup; use --offline to request zero registry/advisory egress.'
    ),
    surface(
      'exploit-intelligence',
      false,
      'https://api.first.org/data/v1/epss and https://www.cisa.gov',
      ['public CVE identifiers'],
      'Conditional public EPSS/CISA KEV enrichment in online mode.'
    ),
    surface(
      'license-metadata',
      options.licenses === true,
      'https://api.deps.dev/v3',
      ['exact public package identity', 'version'],
      'Requires --licenses; private and scoped identity rules remain in force.'
    ),
    surface(
      'package-health',
      options.packageHealth === true,
      'https://registry.npmjs.org',
      ['public npm package name', 'version'],
      'Requires --package-health; private namespace disclosure needs explicit consent.'
    ),
    surface(
      'npm-provenance',
      options.npmProvenancePolicy === true,
      'https://registry.npmjs.org',
      ['trusted public npm package identity', 'artifact integrity metadata'],
      'Requires --npm-provenance-policy outside the scanned project.'
    ),
    surface(
      'go-module-resolution',
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
