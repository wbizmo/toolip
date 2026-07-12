import type { Command } from 'commander';
import { DepsDevClient } from '../providers/depsdev/client.js';

type PackageHealthOptions = {
  json?: boolean;
};

export function registerPackageHealthCommand(
  program: Command
): void {
  program
    .command('package-health <package> [version]')
    .description(
      'Inspect npm package health and provenance through deps.dev.'
    )
    .option('--json', 'Print structured JSON.')
    .action(
      async (
        packageName: string,
        version: string | undefined,
        options: PackageHealthOptions
      ) => {
        if (!version) {
          throw new Error(
            'A resolved package version is required.'
          );
        }

        const client = new DepsDevClient();

        const [metadata, dependencies] =
          await Promise.all([
            client.getVersion(
              packageName,
              version
            ),
            client.getDependencies(
              packageName,
              version
            )
          ]);

        const result = {
          package: packageName,
          version,
          publishedAt: metadata.publishedAt,
          deprecated:
            metadata.isDeprecated ?? false,
          deprecatedReason:
            metadata.deprecatedReason,
          licenses:
            metadata.licenses ?? [],
          advisories:
            metadata.advisoryKeys
              ?.map((item) => item.id)
              .filter(
                (value): value is string =>
                  Boolean(value)
              ) ?? [],
          verifiedProvenance:
            (metadata.slsaProvenances ?? [])
              .filter(
                (item) =>
                  item.verified === true
              ).length,
          verifiedAttestations:
            (metadata.attestations ?? [])
              .filter(
                (item) =>
                  item.verified === true
              ).length,
          relatedProjects:
            metadata.relatedProjects ?? [],
          dependencyNodes:
            dependencies.nodes?.length ?? 0,
          dependencyEdges:
            dependencies.edges?.length ?? 0
        };

        if (options.json) {
          console.log(
            JSON.stringify(result, null, 2)
          );
          return;
        }

        console.log('Toolip Package Health');
        console.log('');
        console.log(
          `Package: ${packageName}@${version}`
        );
        console.log(
          `Published: ${result.publishedAt ?? 'unknown'}`
        );
        console.log(
          `Deprecated: ${result.deprecated}`
        );
        console.log(
          `Licenses: ${
            result.licenses.join(', ') || 'unknown'
          }`
        );
        console.log(
          `Advisories: ${result.advisories.length}`
        );
        console.log(
          `Dependency nodes: ${result.dependencyNodes}`
        );
        console.log(
          `Verified provenance: ${result.verifiedProvenance}`
        );
        console.log(
          `Verified attestations: ${result.verifiedAttestations}`
        );
      }
    );
}
