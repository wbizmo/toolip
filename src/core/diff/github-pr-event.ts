import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import { ToolipError } from '../../errors/toolip-error.js';

const maximumEventBytes = 1024 * 1024;
const repositoryName = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const commitSha = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
const nonBlocking = process.platform === 'win32' ? 0 : constants.O_NONBLOCK;

const repositorySchema = z
  .object({
    id: z.number().int().positive().safe(),
    full_name: z.string().regex(repositoryName)
  })
  .passthrough();

const endpointSchema = z
  .object({
    sha: z.string().regex(commitSha),
    repo: repositorySchema
  })
  .passthrough();

const pullRequestEventSchema = z
  .object({
    action: z.enum([
      'opened',
      'reopened',
      'synchronize',
      'edited',
      'ready_for_review',
      'converted_to_draft'
    ]),
    repository: repositorySchema,
    pull_request: z
      .object({
        number: z.number().int().positive().safe(),
        base: endpointSchema,
        head: endpointSchema
      })
      .passthrough()
  })
  .passthrough();

export type GitHubPullRequestEventContext = Readonly<{
  action: z.infer<typeof pullRequestEventSchema>['action'];
  repository: string;
  pullRequestNumber: number;
  baseSha: string;
  headSha: string;
  headRepository: string;
}>;

/** Parses only the bounded metadata needed to bind a scan to a GitHub PR. */
export function parseGitHubPullRequestEvent(
  source: string,
  expectedRepository: string
): GitHubPullRequestEventContext {
  if (!repositoryName.test(expectedRepository)) throw invalidEvent();

  let value: unknown;
  try {
    const document = parseDocument(source, {
      schema: 'json',
      uniqueKeys: true,
      prettyErrors: false
    });
    if (document.errors.length > 0) throw invalidEvent();
    value = document.toJS();
  } catch {
    throw invalidEvent();
  }

  const parsed = pullRequestEventSchema.safeParse(value);
  if (!parsed.success) throw invalidEvent();

  const event = parsed.data;
  if (
    event.repository.full_name !== expectedRepository ||
    event.pull_request.base.repo.id !== event.repository.id ||
    event.pull_request.base.repo.full_name !== event.repository.full_name
  )
    throw invalidEvent();

  return Object.freeze({
    action: event.action,
    repository: event.repository.full_name,
    pullRequestNumber: event.pull_request.number,
    baseSha: event.pull_request.base.sha,
    headSha: event.pull_request.head.sha,
    headRepository: event.pull_request.head.repo.full_name
  });
}

/** Reads GitHub's event file as bounded inert data without following links. */
export async function readGitHubPullRequestEvent(
  filePath: string,
  expectedRepository: string
): Promise<GitHubPullRequestEventContext> {
  let source: string;
  try {
    source = await readBoundedEventFile(filePath);
  } catch {
    throw invalidEvent();
  }
  return parseGitHubPullRequestEvent(source, expectedRepository);
}

async function readBoundedEventFile(filePath: string): Promise<string> {
  const absolutePath = path.resolve(filePath);
  const before = await lstat(absolutePath, { bigint: true });
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.size > BigInt(maximumEventBytes)
  )
    throw invalidEvent();

  const handle = await open(
    absolutePath,
    constants.O_RDONLY | noFollow | nonBlocking
  );
  try {
    const opened = await handle.stat({ bigint: true });
    const namedAfterOpen = await lstat(absolutePath, { bigint: true });
    if (
      !opened.isFile() ||
      namedAfterOpen.isSymbolicLink() ||
      !namedAfterOpen.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      opened.mtimeNs !== before.mtimeNs ||
      opened.ctimeNs !== before.ctimeNs ||
      namedAfterOpen.dev !== opened.dev ||
      namedAfterOpen.ino !== opened.ino
    )
      throw invalidEvent();

    const buffer = Buffer.alloc(maximumEventBytes + 1);
    let total = 0;
    while (total <= maximumEventBytes) {
      const result = await handle.read(
        buffer,
        total,
        Math.min(64 * 1024, maximumEventBytes + 1 - total),
        total
      );
      if (result.bytesRead === 0) break;
      total += result.bytesRead;
    }
    if (total > maximumEventBytes || BigInt(total) !== before.size)
      throw invalidEvent();

    const after = await handle.stat({ bigint: true });
    const namedAfterRead = await lstat(absolutePath, { bigint: true });
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      namedAfterRead.isSymbolicLink() ||
      !namedAfterRead.isFile() ||
      namedAfterRead.dev !== opened.dev ||
      namedAfterRead.ino !== opened.ino
    )
      throw invalidEvent();

    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(
        buffer.subarray(0, total)
      );
    } catch {
      throw invalidEvent();
    }
  } finally {
    await handle.close();
  }
}

function invalidEvent(): ToolipError {
  return new ToolipError(
    'GitHub pull request event is missing, malformed, stale or unsafe.',
    { code: 'GITHUB_EVENT_INVALID', exitCode: 1 }
  );
}
