import { constants } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { parseDocument } from 'yaml';
import { TOOLIP_VERSION } from '../config/version.js';
import { scannerArtifactDigest } from '../core/report-signature.js';
import {
  createNpmTarballAttestation,
  verifyNpmTarballAttestation
} from '../core/npm-package-attestation.js';

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
  const absolute = path.resolve(filePath);
  const named = await lstat(absolute, { bigint: true });
  if (
    named.isSymbolicLink() ||
    !named.isFile() ||
    named.size === 0n ||
    named.size > BigInt(maximumBytes)
  )
    throw new Error(`${description} must be a bounded regular non-symlink file.`);

  const handle = await open(
    absolute,
    constants.O_RDONLY |
      (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
  );
  try {
    const opened = await handle.stat({ bigint: true });
    const after = await lstat(absolute, { bigint: true });
    if (
      !opened.isFile() ||
      after.isSymbolicLink() ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size > BigInt(maximumBytes)
    )
      throw new Error(`${description} changed while it was being opened.`);
    const bytes = await handle.readFile();
    const finished = await handle.stat({ bigint: true });
    const finalPath = await lstat(absolute, { bigint: true });
    if (
      bytes.length === 0 ||
      bytes.length > maximumBytes ||
      BigInt(bytes.length) !== opened.size
    )
      throw new Error(`${description} exceeds the size limit.`);
    if (
      finished.dev !== opened.dev ||
      finished.ino !== opened.ino ||
      finished.size !== opened.size ||
      finished.mtimeNs !== opened.mtimeNs ||
      finished.ctimeNs !== opened.ctimeNs ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.isSymbolicLink()
    )
      throw new Error(`${description} changed while it was being read.`);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function createBundleFile(filePath: string, bundle: unknown): Promise<void> {
  const bytes = Buffer.from(`${JSON.stringify(bundle)}\n`, 'utf8');
  if (bytes.length > maximumBundleBytes)
    throw new Error('Generated npm attestation bundle exceeds 16 MiB.');
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
        `${JSON.stringify({
          packageName: result.identity.name,
          packageVersion: result.identity.version,
          tarballSha512: result.sha512,
          scannerArtifactSha256
        })}\n`
      );
    });

  command
    .command('verify')
    .description(
      'Verify an exact tarball and bundle against explicit Sigstore and source identities.'
    )
    .requiredOption('--tarball <file>', 'Exact npm .tgz file to verify.')
    .requiredOption('--bundle <file>', 'Sigstore bundle created for this tarball.')
    .requiredOption('--certificate-issuer <url>', 'Expected OIDC certificate issuer.')
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
      process.stdout.write(`${JSON.stringify(result)}\n`);
      if (result.status !== 'verified')
        throw new Error(
          `npm package attestation did not verify (${result.status}: ${result.reason}).`
        );
    });
}
