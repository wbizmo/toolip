import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { explainScanEgress } from '../core/privacy-egress.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

/** Offline, explanatory command: does not inspect source or call providers. */
export function registerPrivacyCommand(program: Command): void {
  program
    .command('privacy')
    .description('Inspect declared local-first privacy and egress behavior.')
    .command('explain')
    .description('Show known scan network destinations and consent gates as JSON.')
    .option('--offline', 'Describe the scan --offline execution mode.')
    .option('--licenses', 'Include opt-in deps.dev license queries.')
    .option('--package-health', 'Include opt-in npm health metadata queries.')
    .option('--npm-provenance-policy', 'Include opt-in npm attestation requests.')
    .option('--allow-go-tool-execution', 'Include opt-in Go module proxy/sumdb commands.')
    .option('--allow-public-scope', 'Declare consent for public scoped npm lookups.')
    .option('--allow-public-cve-lookup', 'Describe optional GHSA and NVD CVE lookups.')
    .action(
      (options: {
        offline?: boolean;
        licenses?: boolean;
        packageHealth?: boolean;
        npmProvenancePolicy?: boolean;
        allowGoToolExecution?: boolean;
        allowPublicScope?: boolean;
        allowPublicCveLookup?: boolean;
      }) => {
        if (options.offline && options.allowGoToolExecution)
          throw new ToolipError(
            '--allow-go-tool-execution cannot be combined with --offline.',
            { code: 'OFFLINE_TOOL_EXECUTION_CONFLICT', exitCode: 1 }
          );
        if (options.offline && options.npmProvenancePolicy)
          throw new ToolipError(
            '--npm-provenance-policy cannot be combined with --offline.',
            { code: 'OFFLINE_PROVENANCE_CONFLICT', exitCode: 1 }
          );
        console.log(serializeJsonOutputBounded(explainScanEgress(options)));
      }
    );
}
