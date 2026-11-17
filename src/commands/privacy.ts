import type { Command } from 'commander';
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
    .action(
      (options: {
        offline?: boolean;
        licenses?: boolean;
        packageHealth?: boolean;
        npmProvenancePolicy?: boolean;
        allowGoToolExecution?: boolean;
        allowPublicScope?: boolean;
      }) => {
        console.log(serializeJsonOutputBounded(explainScanEgress(options)));
      }
    );
}
