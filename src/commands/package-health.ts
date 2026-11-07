import type { Command } from 'commander';
import { readNpmDependencyInventory } from '../core/dependencies/inventory.js';
import {
  DepsDevClient,
  summarizeDepsDevTrust
} from '../providers/depsdev/client.js';
import { NpmPackageHealthClient } from '../providers/npm/package-health.js';

type PackageHealthOptions = {
  json?: boolean;
  allowPublicScope?: boolean;
  offline?: boolean;
  path?: string;
};

export async function inspectProjectPackageHealth(
  root: string,
  options: Pick<PackageHealthOptions, 'allowPublicScope' | 'offline'> = {}
) {
  const inventory = await readNpmDependencyInventory(root);
  const client = new NpmPackageHealthClient({
    allowScopedPublicPackage: options.allowPublicScope === true,
    offline: options.offline === true
  });
  const observations = await client.inspectMany(
    inventory.map(({ name, version, installPath, registry }) => ({
      name,
      version,
      installPath,
      registry
    }))
  );
  const lockEntries = new Map(
    inventory.map((item) => [item.installPath, item] as const)
  );
  return observations.map(({ name, version, installPath, health }) => {
    const locked = lockEntries.get(installPath);
    return {
      package: name,
      version,
      installPath,
      resolutionConfidence: locked?.resolutionConfidence ?? 'unknown',
      registryOrigin: locked?.registry,
      resolvedArtifact: locked?.resolved,
      lockIntegrity: locked?.integrity,
      status: health.status,
      maintainerHistoryStatus: health.maintainerHistoryStatus,
      publisherHistoryStatus: health.publisherHistoryStatus,
      releaseHistoryStatus: health.releaseHistoryStatus,
      signals: health.signals,
      deprecated: health.deprecated,
      lastPublishedAt: health.lastPublishedAt,
      releaseCount7Days: health.releaseCount7Days,
      installScripts: health.installScripts,
      sourceRepository: health.sourceRepository,
      warnings: health.warnings
    };
  });
}

export function registerPackageHealthCommand(program: Command): void {
  program
    .command('package-health [package] [version]')
    .description(
      'Inspect exact-version npm health and provider-reported release signals.'
    )
    .option('--json', 'Print structured JSON.')
    .option(
      '--allow-public-scope',
      'Confirm this scoped name is public before sending it to npm and deps.dev.'
    )
    .option('--offline', 'Do not query public package metadata providers.')
    .option(
      '--path <directory>',
      'Inspect exact npm package instances in a project lockfile.'
    )
    .action(
      async (
        packageName: string | undefined,
        version: string | undefined,
        options: PackageHealthOptions
      ) => {
        if (options.path) {
          if (packageName || version) {
            throw new Error(
              'Use either --path or a package name and exact version, not both.'
            );
          }
          const observations = await inspectProjectPackageHealth(
            options.path,
            options
          );
          if (options.json) {
            console.log(JSON.stringify(observations, null, 2));
            return;
          }
          console.log('Toolip Project Package Health');
          console.log('');
          for (const item of observations) {
            console.log(
              `${item.package}@${item.version} (${item.installPath}): ${item.status}`
            );
            for (const signal of item.signals) {
              console.log(
                `  Review signal (${signal.confidence}): ${signal.id} — ${signal.evidence}`
              );
            }
            if (item.warnings.length > 0) {
              console.log(`  Unknown: ${item.warnings.join(', ')}`);
            }
          }
          console.log(
            'Registry activity signals are review evidence, not a malicious-package verdict.'
          );
          return;
        }
        if (!packageName) {
          throw new Error('Provide a package name or use --path <directory>.');
        }
        if (!version) {
          throw new Error('A resolved package version is required.');
        }

        const scoped = packageName.startsWith('@');
        const npmClient = new NpmPackageHealthClient({
          allowScopedPublicPackage: options.allowPublicScope === true,
          offline: options.offline === true
        });
        const npmHealth = await npmClient.inspect(packageName, version);
        let depsDevStatus: 'available' | 'partial' | 'not_queried';
        let metadata:
          Awaited<ReturnType<DepsDevClient['getVersion']>> | undefined;
        let dependencies:
          Awaited<ReturnType<DepsDevClient['getDependencies']>> | undefined;
        if (options.offline) {
          depsDevStatus = 'not_queried';
        } else if (scoped && !options.allowPublicScope) {
          depsDevStatus = 'not_queried';
        } else {
          const client = new DepsDevClient();
          const [versionResult, dependencyResult] = await Promise.allSettled([
            client.getVersion(packageName, version),
            client.getDependencies(packageName, version)
          ]);
          metadata =
            versionResult.status === 'fulfilled'
              ? versionResult.value
              : undefined;
          dependencies =
            dependencyResult.status === 'fulfilled'
              ? dependencyResult.value
              : undefined;
          depsDevStatus =
            versionResult.status === 'fulfilled' &&
            dependencyResult.status === 'fulfilled'
              ? 'available'
              : 'partial';
        }

        const result = {
          package: packageName,
          version,
          status:
            npmHealth.status === 'unavailable' || depsDevStatus === 'partial'
              ? 'partial'
              : npmHealth.status,
          providerStatus: {
            npmRegistry: npmHealth.status,
            depsDev: depsDevStatus
          },
          publishedAt: metadata?.publishedAt ?? npmHealth.lastPublishedAt,
          deprecated: metadata?.isDeprecated ?? npmHealth.deprecated ?? false,
          deprecatedReason: metadata?.deprecatedReason,
          licenses: metadata?.licenses ?? [],
          advisories:
            metadata?.advisoryKeys
              ?.map((item) => item.id)
              .filter((value): value is string => Boolean(value)) ?? [],
          trustMetadata: summarizeDepsDevTrust(metadata),
          relatedProjects: metadata?.relatedProjects ?? [],
          dependencyNodes: dependencies?.nodes?.length ?? 0,
          dependencyEdges: dependencies?.edges?.length ?? 0,
          maintainersObserved: npmHealth.maintainersObserved,
          publisherChangesObserved: npmHealth.publisherChangesObserved,
          releaseCount7Days: npmHealth.releaseCount7Days,
          installScripts: npmHealth.installScripts ?? [],
          sourceRepository: npmHealth.sourceRepository,
          signals: npmHealth.signals,
          warnings: [
            ...npmHealth.warnings,
            ...(depsDevStatus === 'partial' ? ['depsdev-provider-partial'] : [])
          ]
        };

        if (options.json) {
          console.log(JSON.stringify(result, null, 2));
          return;
        }

        console.log('Toolip Package Health');
        console.log('');
        console.log(`Package: ${packageName}@${version}`);
        console.log(`Published: ${result.publishedAt ?? 'unknown'}`);
        console.log(`Deprecated: ${result.deprecated}`);
        console.log(`Licenses: ${result.licenses.join(', ') || 'unknown'}`);
        console.log(`Advisories: ${result.advisories.length}`);
        console.log(`Dependency nodes: ${result.dependencyNodes}`);
        console.log(
          `deps.dev provenance records: ${result.trustMetadata.provenance.records} (${result.trustMetadata.provenance.recordsMarkedVerifiedByProvider} marked verified by provider)`
        );
        console.log(
          `deps.dev attestation records: ${result.trustMetadata.attestations.records} (${result.trustMetadata.attestations.recordsMarkedVerifiedByProvider} marked verified by provider)`
        );
        console.log(
          'Toolip did not independently verify these attestation signatures or source identities.'
        );
        console.log(
          `Provider status: npm=${npmHealth.status}, deps.dev=${depsDevStatus}`
        );
        for (const signal of npmHealth.signals) {
          console.log(
            `Review signal (${signal.confidence}): ${signal.id} — ${signal.evidence}`
          );
        }
        if (scoped && !options.allowPublicScope) {
          console.log(
            'Scoped package name was not sent to public metadata providers; pass --allow-public-scope only for a known-public package.'
          );
        }
        console.log(
          'Registry activity signals are review evidence, not a malicious-package verdict.'
        );
      }
    );
}
