import {
  mkdir,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import {
  generateSbom,
  type SbomFormat
} from '../core/sbom/generate.js';

type SbomOptions = {
  path: string;
  format: SbomFormat;
  output?: string;
};

function assertFormat(
  value: string
): asserts value is SbomFormat {
  if (
    value !== 'cyclonedx' &&
    value !== 'spdx'
  ) {
    throw new Error(
      'SBOM format must be cyclonedx or spdx.'
    );
  }
}

export function registerSbomCommand(
  program: Command
): void {
  program
    .command('sbom')
    .description(
      'Generate a CycloneDX 1.5 or SPDX 2.3 software bill of materials.'
    )
    .option(
      '-p, --path <path>',
      'Project path to inspect.',
      process.cwd()
    )
    .option(
      '-f, --format <format>',
      'cyclonedx or spdx.',
      'cyclonedx'
    )
    .option(
      '-o, --output <file>',
      'Write JSON to a file instead of stdout.'
    )
    .action(async (options: SbomOptions) => {
      assertFormat(options.format);

      const document = await generateSbom(
        options.path,
        options.format
      );

      const output =
        `${JSON.stringify(document, null, 2)}\n`;

      if (!options.output) {
        process.stdout.write(output);
        return;
      }

      const outputPath = path.resolve(
        options.path,
        options.output
      );

      await mkdir(path.dirname(outputPath), {
        recursive: true
      });

      await writeFile(
        outputPath,
        output,
        'utf8'
      );

      console.log(`SBOM written to ${outputPath}`);
    });
}
