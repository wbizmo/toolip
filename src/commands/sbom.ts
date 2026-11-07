import { constants } from 'node:fs';
import { lstat, mkdir, open, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { TOOLIP_VERSION } from '../config/version.js';
import { scannerArtifactDigest } from '../core/report-signature.js';
import { readPemKeyFile } from '../core/secure-key-file.js';
import {
  signSbomAttestation,
  verifySbomAttestation
} from '../core/sbom/attestation.js';
import {
  createProjectSnapshot,
  dependencyFileSourceFromSnapshot
} from '../application/project-snapshot.js';
import { generateSbom, type SbomFormat } from '../core/sbom/generate.js';
import type { GoCommandRunner } from '../core/dependencies/go-module-graph.js';

type SbomOptions = {
  path: string;
  format: SbomFormat;
  output?: string;
  signingKey?: string;
  signingKeyId?: string;
  projectId?: string;
  attestationOutput?: string;
  allowGoToolExecution?: boolean;
  goCommandRunner?: GoCommandRunner;
};

const maximumJsonBytes = 32 * 1024 * 1024;

async function readBoundedJson(filePath: string): Promise<unknown> {
  const absolute = path.resolve(filePath);
  const named = await lstat(absolute);
  if (
    named.isSymbolicLink() ||
    !named.isFile() ||
    named.size > maximumJsonBytes
  )
    throw new Error('SBOM input must be a bounded regular non-symlink file.');
  const handle = await open(
    absolute,
    constants.O_RDONLY |
      (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
  );
  try {
    const opened = await handle.stat();
    const after = await lstat(absolute);
    if (
      !opened.isFile() ||
      after.isSymbolicLink() ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size > maximumJsonBytes
    )
      throw new Error('SBOM input changed while it was being opened.');
    const bytes = await handle.readFile();
    if (bytes.length > maximumJsonBytes)
      throw new Error('SBOM input exceeds the size limit.');
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    await handle.close();
  }
}

function assertFormat(value: string): asserts value is SbomFormat {
  if (value !== 'cyclonedx' && value !== 'spdx') {
    throw new Error('SBOM format must be cyclonedx or spdx.');
  }
}

export function registerSbomCommand(program: Command): void {
  const sbom = program
    .command('sbom')
    .description(
      'Generate a CycloneDX 1.5 or SPDX 2.3 software bill of materials.'
    )
    .option('-p, --path <path>', 'Project path to inspect.', process.cwd())
    .option('-f, --format <format>', 'cyclonedx or spdx.', 'cyclonedx')
    .option('-o, --output <file>', 'Write JSON to a file instead of stdout.')
    .option(
      '--allow-go-tool-execution',
      'Explicitly run Go module graph commands on the captured metadata; may query proxy.golang.org and sum.golang.org.'
    )
    .option(
      '--signing-key <file>',
      'Owner-only Ed25519 private key for a DSSE attestation.'
    )
    .option(
      '--signing-key-id <id>',
      'Trusted key identifier embedded in the attestation.'
    )
    .option(
      '--project-id <id>',
      'Stable expected project identity embedded in the attestation.'
    )
    .option(
      '--attestation-output <file>',
      'Detached DSSE/in-toto sidecar path.'
    )
    .action(async (options: SbomOptions) => {
      assertFormat(options.format);

      const signingOptions = [
        options.signingKey,
        options.signingKeyId,
        options.projectId
      ];
      const signingRequested = signingOptions.some(Boolean);
      if (
        signingRequested &&
        (!options.signingKey || !options.signingKeyId || !options.projectId)
      )
        throw new Error(
          'SBOM signing requires --signing-key, --signing-key-id, and --project-id.'
        );
      if (signingRequested && !options.output)
        throw new Error(
          'Signed SBOM output requires --output so its sidecar can bind to a file.'
        );
      if (options.attestationOutput && !signingRequested)
        throw new Error('--attestation-output requires SBOM signing options.');

      const snapshot = await createProjectSnapshot(options.path);
      if (options.allowGoToolExecution)
        console.error(
          'Go MVS resolution is enabled and may contact the official Go module proxy and checksum database.'
        );
      const document = await generateSbom(snapshot.root, options.format, {
        fileSource: dependencyFileSourceFromSnapshot(snapshot),
        allowGoToolExecution: options.allowGoToolExecution,
        goCommandRunner: options.goCommandRunner
      });

      const output = `${JSON.stringify(document, null, 2)}\n`;

      let attestationText: string | undefined;
      if (options.signingKey && options.signingKeyId && options.projectId) {
        const privateKeyPem = await readPemKeyFile(options.signingKey, {
          privateKey: true
        });
        const attestation = signSbomAttestation(document, {
          privateKeyPem,
          keyId: options.signingKeyId,
          projectId: options.projectId,
          toolipVersion: TOOLIP_VERSION,
          scannerArtifactSha256: await scannerArtifactDigest(),
          source: {
            ...(snapshot.gitHeadRevision
              ? { gitRevision: snapshot.gitHeadRevision }
              : {}),
            ...(snapshot.lockGraphDigest
              ? { lockGraphDigest: snapshot.lockGraphDigest }
              : {}),
            ...(snapshot.configDigest
              ? { configDigest: snapshot.configDigest }
              : {})
          }
        });
        attestationText = `${JSON.stringify(attestation, null, 2)}\n`;
      }

      if (!options.output) {
        process.stdout.write(output);
        return;
      }

      const outputPath = path.resolve(snapshot.root, options.output);
      const attestationPath = options.attestationOutput
        ? path.resolve(snapshot.root, options.attestationOutput)
        : `${outputPath}.attestation.json`;
      if (attestationText && attestationPath === outputPath)
        throw new Error('SBOM and attestation output paths must be different.');

      await mkdir(path.dirname(outputPath), {
        recursive: true
      });

      await writeFile(outputPath, output, 'utf8');

      if (attestationText) {
        await mkdir(path.dirname(attestationPath), { recursive: true });
        await writeFile(attestationPath, attestationText, {
          encoding: 'utf8',
          flag: 'wx',
          mode: 0o644
        });
        console.log(`DSSE attestation written to ${attestationPath}`);
      }

      console.log(`SBOM written to ${outputPath}`);
    });

  sbom
    .command('verify <file>')
    .description(
      'Verify a signed SBOM sidecar against an exact document and trusted identity.'
    )
    .requiredOption(
      '--attestation <file>',
      'Detached DSSE/in-toto sidecar file.'
    )
    .requiredOption(
      '--public-key <file>',
      'Trusted Ed25519 public key PEM file.'
    )
    .requiredOption('--key-id <id>', 'Expected signing key identifier.')
    .requiredOption('--project-id <id>', 'Expected stable project identity.')
    .option(
      '--scanner-artifact-sha256 <digest>',
      'Require this exact trusted Toolip runtime artifact digest.'
    )
    .option('--max-age-days <days>', 'Maximum accepted attestation age.', '90')
    .action(
      async (
        file: string,
        options: {
          attestation: string;
          publicKey: string;
          keyId: string;
          projectId: string;
          scannerArtifactSha256?: string;
          maxAgeDays: string;
        }
      ) => {
        const maxAgeDays = Number(options.maxAgeDays);
        if (!Number.isFinite(maxAgeDays) || maxAgeDays < 0 || maxAgeDays > 365)
          throw new Error('--max-age-days must be between 0 and 365.');
        const [document, attestation, publicKeyPem] = await Promise.all([
          readBoundedJson(file),
          readBoundedJson(options.attestation),
          readPemKeyFile(options.publicKey)
        ]);
        const verification = verifySbomAttestation(document, attestation, {
          publicKeyPem,
          trustedKeyId: options.keyId,
          expectedProjectId: options.projectId,
          expectedScannerArtifactSha256: options.scannerArtifactSha256,
          maxAgeMs: maxAgeDays * 24 * 60 * 60 * 1000
        });
        process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
        if (verification.status !== 'verified') process.exitCode = 2;
      }
    );
}
