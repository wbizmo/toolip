import { constants } from 'node:fs';
import { mkdir, open } from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { parseDocument } from 'yaml';
import { TOOLIP_VERSION } from '../config/version.js';
import { scannerArtifactDigest } from '../core/report-signature.js';
import {
  createNpmTarballAttestation,
  verifyNpmTarballAttestation
} from '../core/npm-package-attestation.js';
import { readBoundedRegularFile as readCappedFile } from '../core/bounded-file.js';
import { serializeJsonOutputWithinBudget } from '../core/report-writer.js';

const maximumTarballBytes = 32 * 1024 * 1024;
const maximumBundleBytes = 16 * 1024 * 1024;

type CreateOptions = {
  tarball: string;
  output: string;
  sourceRepository: string;
  sourceCommit: string;
};

type VerifyOptions = {
  tarball: string;
  bundle: string;
  certificateIssuer: string;
  certificateIdentity: string;
  sourceRepository: string;
  sourceCommit: string;
  scannerArtifactSha256: string;
};

async function readBoundedRegularFile(
  filePath: string,
  maximumBytes: number,
  description: string
): Promise<Buffer> {
  try {
    const bytes = await readCappedFile(path.resolve(filePath), maximumBytes);
    if (bytes.length === 0) throw new Error(`${description} is empty.`);
    return bytes;
  } catch {
    throw new Error(`${description} is not a stable bounded regular file.`);
  }
}

async function createBundleFile(
  filePath: string,
  bundle: unknown
): Promise<void> {
  const bytes = Buffer.from(
    `${serializeJsonOutputWithinBudget(bundle, maximumBundleBytes - 1)}\n`,
    'utf8'
  );
  const absolute = path.resolve(filePath);
  await mkdir(path.dirname(absolute), { recursive: true });
  const handle = await open(
    absolute,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW),
    0o600
  );
  try {
    await handle.writeFile(bytes);
  } finally {
    await handle.close();
  }
}

async function readBundle(filePath: string): Promise<unknown> {
  const bytes = await readBoundedRegularFile(
    filePath,
    maximumBundleBytes,
    'Sigstore bundle'
  );
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const document = parseDocument(source, {
    uniqueKeys: true,
    prettyErrors: false
  });
  if (document.errors.length)
    throw new Error('Sigstore bundle is malformed or has duplicate keys.');
  try {
    return JSON.parse(source) as unknown;
  } catch {
    throw new Error('Sigstore bundle must be valid JSON.');
  }
}

export function registerNpmAttestationCommand(program: Command): void {
  const command = program
    .command('npm-attestation')
    .description(
      'Create or verify Sigstore attestations for exact packed npm tarballs.'
    );

  command
    .command('create')
    .description(
      'Sign a packed npm tarball using the current runner OIDC identity.'
    )
    .requiredOption('--tarball <file>', 'Exact npm .tgz file to attest.')
    .requiredOption('--output <file>', 'Create a new Sigstore bundle file.')
    .requiredOption(
      '--source-repository <url>',
      'Canonical GitHub repository that produced this release.'
    )
    .requiredOption(
      '--source-commit <sha>',
      'Full 40-character Git commit represented by the release.'
    )
    .action(async (options: CreateOptions) => {
      const tarball = await readBoundedRegularFile(
        options.tarball,
        maximumTarballBytes,
        'npm tarball'
      );
      const scannerArtifactSha256 = await scannerArtifactDigest();
      const result = await createNpmTarballAttestation(tarball, {
        sourceRepository: options.sourceRepository,
        sourceCommit: options.sourceCommit,
        toolipVersion: TOOLIP_VERSION,
        scannerArtifactSha256
      });
      await createBundleFile(options.output, result.bundle);
      process.stdout.write(
        `${serializeJsonOutputWithinBudget(
          {
            packageName: result.identity.name,
            packageVersion: result.identity.version,
            tarballSha512: result.sha512,
            scannerArtifactSha256
          },
          1023
        )}\n`
      );
    });

  command
    .command('verify')
    .description(
      'Verify an exact tarball and bundle against explicit Sigstore and source identities.'
    )
    .requiredOption('--tarball <file>', 'Exact npm .tgz file to verify.')
    .requiredOption(
      '--bundle <file>',
      'Sigstore bundle created for this tarball.'
    )
    .requiredOption(
      '--certificate-issuer <url>',
      'Expected OIDC certificate issuer.'
    )
    .requiredOption(
      '--certificate-identity <uri>',
      'Expected exact OIDC certificate identity URI.'
    )
    .requiredOption(
      '--source-repository <url>',
      'Expected canonical GitHub source repository.'
    )
    .requiredOption(
      '--source-commit <sha>',
      'Expected full Git commit represented by the release.'
    )
    .requiredOption(
      '--scanner-artifact-sha256 <sha256>',
      'Expected digest of the scanner runtime that created the bundle.'
    )
    .action(async (options: VerifyOptions) => {
      const tarball = await readBoundedRegularFile(
        options.tarball,
        maximumTarballBytes,
        'npm tarball'
      );
      const bundle = await readBundle(options.bundle);
      const result = await verifyNpmTarballAttestation(tarball, bundle, {
        certificateIssuer: options.certificateIssuer,
        certificateIdentity: options.certificateIdentity,
        expectedSourceRepository: options.sourceRepository,
        expectedSourceCommit: options.sourceCommit,
        expectedScannerArtifactSha256: options.scannerArtifactSha256
      });
      process.stdout.write(
        `${serializeJsonOutputWithinBudget(result, 64 * 1024 - 1)}\n`
      );
      if (result.status !== 'verified')
        throw new Error(
          `npm package attestation did not verify (${result.status}: ${result.reason}).`
        );
    });
}
