import type { Command } from 'commander';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { z } from 'zod';
import {
  createGitHubAppScorecardScanner,
  GitHubAppWebhookService
} from '../core/github/app-webhook.js';
import { GitHubAppApiClient } from '../core/github/app-api.js';

const configurationSchema = z
  .object({
    version: z.literal(1),
    repositories: z
      .array(
        z
          .object({
            name: z
              .string()
              .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u)
              .refine((name) =>
                name.split('/').every((part) => part !== '.' && part !== '..')
              ),
            installationId: z.number().int().positive().safe(),
            repositoryId: z.number().int().positive().safe(),
            root: z.string().min(1).max(4_096)
          })
          .strict()
      )
      .min(1)
      .max(100)
  })
  .strict();

export type GitHubAppConfiguration = z.infer<typeof configurationSchema>;

/** Loads a bounded, no-follow local allowlist without exposing its contents. */
export async function loadGitHubAppConfiguration(
  filePath: string
): Promise<GitHubAppConfiguration> {
  const maximumBytes = 256 * 1024;
  const absolutePath = path.resolve(filePath);
  const before = await lstat(absolutePath, { bigint: true });
  if (!before.isFile() || before.size > BigInt(maximumBytes))
    throw new Error('GitHub App configuration must be a bounded regular file.');
  const handle = await open(
    absolutePath,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
  );
  let bytes: Buffer;
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    )
      throw new Error('GitHub App configuration changed while opening.');
    bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(absolutePath, { bigint: true });
    if (
      bytes.byteLength > maximumBytes ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size !== after.size ||
      opened.mtimeNs !== after.mtimeNs ||
      opened.ctimeNs !== after.ctimeNs ||
      afterPath.isSymbolicLink() ||
      afterPath.dev !== opened.dev ||
      afterPath.ino !== opened.ino
    )
      throw new Error('GitHub App configuration changed while reading.');
  } finally {
    await handle.close();
  }
  let document: unknown;
  try {
    document = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    );
  } catch {
    throw new Error('GitHub App configuration is not valid UTF-8 JSON.');
  }
  const parsed = configurationSchema.safeParse(document);
  if (
    !parsed.success ||
    parsed.data.repositories.some((repo) => !path.isAbsolute(repo.root))
  )
    throw new Error(
      'GitHub App configuration does not match the supported schema.'
    );
  if (
    new Set(parsed.data.repositories.map((repo) => repo.name.toLowerCase()))
      .size !== parsed.data.repositories.length
  )
    throw new Error(
      'GitHub App configuration contains duplicate repositories.'
    );
  return parsed.data;
}

type ServeOptions = {
  config: string;
  host: string;
  port: string;
  scheduleHours: string;
  stateFile: string;
  offline?: boolean;
};

async function serve(options: ServeOptions): Promise<void> {
  const secret = process.env.TOOLIP_GITHUB_APP_WEBHOOK_SECRET;
  const appId = process.env.TOOLIP_GITHUB_APP_ID;
  const privateKey = process.env.TOOLIP_GITHUB_APP_PRIVATE_KEY;
  if (!secret || !appId || !privateKey)
    throw new Error(
      'Set TOOLIP_GITHUB_APP_WEBHOOK_SECRET, TOOLIP_GITHUB_APP_ID, and TOOLIP_GITHUB_APP_PRIVATE_KEY before starting the webhook service.'
    );
  const port = Number(options.port);
  const scheduleHours = Number(options.scheduleHours);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535)
    throw new Error('--port must be between 0 and 65535.');
  if (
    !Number.isFinite(scheduleHours) ||
    scheduleHours < 0 ||
    scheduleHours > 168
  )
    throw new Error('--schedule-hours must be between 0 and 168.');
  const configuration = await loadGitHubAppConfiguration(options.config);
  const api = new GitHubAppApiClient({ appId, privateKey });
  const service = new GitHubAppWebhookService({
    webhookSecret: secret,
    repositories: configuration.repositories,
    stateFile: options.stateFile,
    scan: createGitHubAppScorecardScanner({ offline: options.offline ?? true }),
    publishResult: (work, repository, summary, signal) =>
      api.createSecurityCheck(work, repository, summary, signal),
    audit(entry) {
      process.stderr.write(`${JSON.stringify(entry)}\n`);
    }
  });
  const listener = await service.listen(port, options.host);
  const address = listener.address();
  const interval =
    scheduleHours > 0
      ? setInterval(
          () => service.scheduleAll(),
          scheduleHours * 60 * 60 * 1_000
        )
      : undefined;
  process.stdout.write(
    `${JSON.stringify({ event: 'github-app-webhook-listening', host: options.host, address, scheduledRepositories: scheduleHours > 0 ? configuration.repositories.length : 0 })}\n`
  );
  await new Promise<void>((resolve) => {
    const stop = (): void => resolve();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  if (interval) clearInterval(interval);
  await service.close();
}

/** Registers the opt-in, read-only GitHub App webhook and schedule runner. */
export function registerGitHubAppCommand(program: Command): void {
  const command = program
    .command('github-app')
    .description('Run an opt-in read-only GitHub App webhook scanner.');
  command
    .command('serve')
    .description(
      'Start a signed-webhook server for allowlisted local checkouts.'
    )
    .option(
      '--config <file>',
      'Local JSON repository allowlist.',
      'toolip.github-app.json'
    )
    .option(
      '--host <host>',
      'Bind address; use a TLS-terminating reverse proxy for public webhooks.',
      '127.0.0.1'
    )
    .option('--port <port>', 'HTTP listen port.', '8787')
    .option(
      '--state-file <file>',
      'Private durable webhook replay/suspension journal.',
      path.join(os.homedir(), '.toolip-github-app-state', 'deliveries.json')
    )
    .option(
      '--schedule-hours <hours>',
      'Run allowlisted scheduled scans at this interval; zero disables scheduling.',
      '24'
    )
    .option(
      '--online',
      'Allow public advisory-provider requests; scoped package names remain withheld.'
    )
    .action(
      async (options: Omit<ServeOptions, 'offline'> & { online?: boolean }) => {
        try {
          await serve({ ...options, offline: options.online !== true });
        } catch (error) {
          const message =
            error instanceof Error
              ? error.message
              : 'GitHub App service failed.';
          process.stderr.write(
            `${JSON.stringify({ event: 'github-app-start-failed', reason: message.slice(0, 300) })}\n`
          );
          process.exitCode = 1;
        }
      }
    );
}
