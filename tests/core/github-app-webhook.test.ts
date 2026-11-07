import { createHmac } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createGitHubAppScorecardScanner,
  GitHubAppWebhookService,
  type GitHubAppScanWork
} from '../../src/core/github/app-webhook.js';
import { cleanupRepos, git, makeRepo, write } from '../helpers/git-repo.js';
import { runGit } from '../../src/core/git/safe-git.js';

const secret = 'toolip-test-webhook-secret-with-at-least-32-bytes';
const roots: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((close) => close()));
  cleanupRepos();
});

function sign(body: string): string {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

async function request(
  service: GitHubAppWebhookService,
  event: string,
  deliveryId: string,
  payload: unknown,
  signature = true
): Promise<{ status: number; body: Record<string, unknown> }> {
  const body = JSON.stringify(payload);
  return service.receiveWebhook({
    body: Buffer.from(body),
    event,
    deliveryId,
    signature: signature ? sign(body) : `sha256=${'0'.repeat(64)}`
  });
}

function payload(
  repository = 'Acme/Service',
  installation = 42,
  revision = 'a'.repeat(40)
) {
  return {
    installation: { id: installation },
    repository: { full_name: repository, id: 123 },
    ref: 'refs/heads/main',
    after: revision,
    deleted: false
  };
}

describe('read-only GitHub App webhook integration', () => {
  it('authenticates raw webhook bytes and deduplicates deliveries before dispatch', async () => {
    let finishScan: (() => void) | undefined;
    const workItems: GitHubAppScanWork[] = [];
    const audit: Array<Record<string, unknown>> = [];
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      scan: async (work) => {
        workItems.push(work);
        await new Promise<void>((resolve) => (finishScan = resolve));
        return { status: 'complete', findingCount: 0, snapshotId: 'snap' };
      },
      audit: (entry) => audit.push({ ...entry })
    });
    roots.push(() => service.close());

    const rejected = await request(
      service,
      'push',
      'delivery-unauth',
      payload(),
      false
    );
    expect(rejected.status).toBe(401);

    const accepted = await request(service, 'push', 'delivery-1', payload());
    expect(accepted.status).toBe(202);
    await viWaitFor(() => expect(workItems).toHaveLength(1));

    const duplicate = await request(service, 'push', 'delivery-1', payload());
    expect(duplicate.status).toBe(202);
    expect(duplicate.body).toMatchObject({ duplicate: true });
    expect(workItems).toHaveLength(1);
    expect(workItems[0]).toMatchObject({
      kind: 'push',
      repository: 'acme/service',
      installationId: 42,
      revision: 'a'.repeat(40)
    });

    finishScan?.();
    await viWaitFor(() =>
      expect(audit.some((entry) => entry.event === 'scan-finished')).toBe(true)
    );
  });

  it('serves the signed webhook route over HTTP without exposing scan details', async () => {
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      scan: async () => ({
        status: 'incomplete',
        findingCount: 0,
        reason: 'private-path'
      })
    });
    const server = await service.listen(0);
    try {
      const address = server.address() as AddressInfo;
      const body = JSON.stringify(payload());
      const result = await fetch(`http://127.0.0.1:${address.port}/webhook`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-github-delivery': 'http-delivery',
          'x-github-event': 'push',
          'x-hub-signature-256': sign(body)
        },
        body
      });
      expect(result.status).toBe(202);
      await expect(result.json()).resolves.toEqual({ accepted: true });
      const missingRoute = await fetch(
        `http://127.0.0.1:${address.port}/other`,
        {
          method: 'POST',
          body
        }
      );
      expect(missingRoute.status).toBe(404);
    } finally {
      await service.close();
    }
  });

  it('ignores repositories outside the configured installation allowlist', async () => {
    let scans = 0;
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      scan: async () => {
        scans++;
        return { status: 'complete', findingCount: 0 };
      }
    });
    roots.push(() => service.close());
    const response = await request(
      service,
      'push',
      'delivery-other-install',
      payload('acme/service', 99)
    );
    expect(response.status).toBe(202);
    expect(response.body).toMatchObject({ ignored: true });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(scans).toBe(0);
  });

  it('suspends an installation and rejects scans until an authenticated unsuspend event', async () => {
    const scanIds: string[] = [];
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      scan: async (work) => {
        scanIds.push(work.deliveryId);
        return { status: 'complete', findingCount: 0 };
      }
    });
    roots.push(() => service.close());
    const installEvent = { action: 'suspend', installation: { id: 42 } };

    expect(
      (await request(service, 'installation', 'suspend-1', installEvent)).status
    ).toBe(202);
    expect(
      (await request(service, 'push', 'push-suspended', payload())).status
    ).toBe(202);
    expect(
      (
        await request(service, 'installation', 'unsuspend-1', {
          action: 'unsuspend',
          installation: { id: 42 }
        })
      ).status
    ).toBe(202);
    expect(
      (await request(service, 'push', 'push-active', payload())).status
    ).toBe(202);
    await viWaitFor(() => expect(scanIds).toEqual(['push-active']));
  });

  it('aborts active scans and drops queued work when an installation is suspended', async () => {
    let markStarted: (() => void) | undefined;
    let aborted = false;
    const started = new Promise<void>((resolve) => (markStarted = resolve));
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      scan: async (_work, _repository, signal) => {
        markStarted?.();
        await new Promise<void>((resolve) =>
          signal.addEventListener(
            'abort',
            () => {
              aborted = true;
              resolve();
            },
            { once: true }
          )
        );
        return { status: 'complete', findingCount: 0 };
      }
    });
    roots.push(() => service.close());
    expect(
      (await request(service, 'push', 'scan-before-suspend', payload())).status
    ).toBe(202);
    await started;
    expect(
      (await request(service, 'push', 'queued-before-suspend', payload()))
        .status
    ).toBe(202);
    expect(
      (
        await request(service, 'installation', 'suspend-active', {
          action: 'suspend',
          installation: { id: 42 }
        })
      ).status
    ).toBe(202);
    expect(aborted).toBe(true);
    expect(
      (await request(service, 'push', 'scan-after-suspend', payload())).body
    ).toMatchObject({ ignored: true });
  });

  it('persists delivery replay and installation suspension across service restarts', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-app-state-')
    );
    const stateFile = path.join(directory, 'state', 'deliveries.json');
    let scans = 0;
    const repository = [
      {
        name: 'acme/service',
        installationId: 42,
        repositoryId: 123,
        root: '/tmp/acme-service'
      }
    ];
    const createService = () =>
      new GitHubAppWebhookService({
        webhookSecret: secret,
        repositories: repository,
        stateFile,
        scan: async () => {
          scans++;
          return { status: 'complete', findingCount: 0 };
        }
      });
    const first = createService();
    const suspended = await request(first, 'installation', 'suspend-restart', {
      action: 'suspend',
      installation: { id: 42 }
    });
    expect(suspended.status).toBe(202);
    await first.close();

    const restarted = createService();
    roots.push(async () => {
      await restarted.close();
      await rm(directory, { recursive: true, force: true });
    });
    const server = await restarted.listen(0);
    expect(restarted.schedule('acme/service')).toBe(false);
    const replay = await request(restarted, 'installation', 'suspend-restart', {
      action: 'unsuspend',
      installation: { id: 42 }
    });
    expect(replay.body).toMatchObject({ duplicate: true });
    const ignored = await request(
      restarted,
      'push',
      'push-after-restart-suspend',
      payload()
    );
    expect(ignored.body).toMatchObject({ ignored: true });
    expect(scans).toBe(0);
    await restarted.close();
    expect(server.address()).toBeNull();
  });

  it('queues scheduled allowlisted scans with API-safe unique delivery IDs', async () => {
    const scheduled: GitHubAppScanWork[] = [];
    const published: string[] = [];
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      scan: async (work) => {
        scheduled.push(work);
        return {
          status: 'complete',
          findingCount: 0,
          revision: 'a'.repeat(40)
        };
      },
      publishResult: async (work) => {
        published.push(work.deliveryId);
      }
    });
    roots.push(() => service.close());

    expect(service.schedule('acme/service')).toBe(true);
    await viWaitFor(() => expect(scheduled).toHaveLength(1));
    await viWaitFor(() => expect(published).toHaveLength(1));
    expect(scheduled[0]).toMatchObject({
      kind: 'scheduled',
      repositoryId: 123,
      installationId: 42
    });
    expect(scheduled[0]?.deliveryId).toMatch(/^scheduled-[a-f0-9-]{36}$/u);
  });

  it('rejects unsafe setup and invalid body-budget configuration', () => {
    expect(
      () =>
        new GitHubAppWebhookService({
          webhookSecret: 'short',
          repositories: [
            {
              name: 'acme/service',
              installationId: 42,
              repositoryId: 123,
              root: '/tmp/service'
            }
          ],
          scan: async () => ({ status: 'complete', findingCount: 0 })
        })
    ).toThrow('at least 32 bytes');
    expect(
      () =>
        new GitHubAppWebhookService({
          webhookSecret: secret,
          repositories: [
            {
              name: '../service',
              installationId: 42,
              repositoryId: 123,
              root: '/tmp/service'
            }
          ],
          scan: async () => ({ status: 'complete', findingCount: 0 })
        })
    ).toThrow('allowlist is invalid');
    expect(
      () =>
        new GitHubAppWebhookService({
          webhookSecret: secret,
          repositories: [
            {
              name: 'acme/service',
              installationId: 42,
              repositoryId: 123,
              root: '/tmp/service'
            }
          ],
          maxBodyBytes: 0,
          scan: async () => ({ status: 'complete', findingCount: 0 })
        })
    ).toThrow('resource limit');
  });

  it('bounds queue capacity and propagates scan timeouts without reporting a pass', async () => {
    const finishers: Array<() => void> = [];
    const scanIds: string[] = [];
    const audit: Array<Record<string, unknown>> = [];
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      maxConcurrentScans: 1,
      maxQueuedScans: 1,
      scanTimeoutMs: 10,
      scan: async (work, _repository, signal) => {
        scanIds.push(work.deliveryId);
        await new Promise<void>((resolve) => {
          finishers.push(resolve);
          signal.addEventListener('abort', resolve, { once: true });
        });
        return {
          status: 'complete',
          findingCount: 0,
          reason: 'safe-to-ignore'
        };
      },
      audit: (entry) => audit.push({ ...entry })
    });
    roots.push(() => service.close());

    expect((await request(service, 'push', 'queued-1', payload())).status).toBe(
      202
    );
    await viWaitFor(() => expect(scanIds).toEqual(['queued-1']));
    expect((await request(service, 'push', 'queued-2', payload())).status).toBe(
      202
    );
    expect((await request(service, 'push', 'queued-3', payload())).status).toBe(
      503
    );
    await viWaitFor(() =>
      expect(
        audit.some(
          (entry) =>
            entry.event === 'scan-finished' &&
            entry.deliveryId === 'queued-1' &&
            entry.status === 'incomplete' &&
            entry.reason === 'scan-cancelled-or-timed-out'
        )
      ).toBe(true)
    );
    finishers.shift()?.();
    await viWaitFor(() => expect(scanIds).toEqual(['queued-1', 'queued-2']));
    finishers.shift()?.();
  });

  it('passes only bounded result summaries to the GitHub check publisher', async () => {
    const published: Array<{
      work: GitHubAppScanWork;
      revision?: string;
      status: string;
      findingCount: number;
      annotations: Array<{ path: string; line: number; ruleId: string }>;
    }> = [];
    const audit: Array<Record<string, unknown>> = [];
    const service = new GitHubAppWebhookService({
      webhookSecret: secret,
      repositories: [
        {
          name: 'acme/service',
          installationId: 42,
          repositoryId: 123,
          root: '/tmp/acme-service'
        }
      ],
      scan: async () => ({
        status: 'complete',
        findingCount: 60,
        revision: 'a'.repeat(40),
        reason: 'a private path must not leave the host',
        annotations: [
          { path: 'a/a.ts', line: 7, severity: 'high', ruleId: 'TLP-TEST-001' },
          {
            path: '../outside.ts',
            line: 1,
            severity: 'critical',
            ruleId: 'TLP-TEST-002'
          },
          {
            path: `secrets/ghp_${'A'.repeat(24)}.ts`,
            line: 1,
            severity: 'critical',
            ruleId: 'TLP-TEST-003'
          },
          ...Array.from({ length: 60 }, (_, index) => ({
            path: `generated/${String(index).padStart(2, '0')}.ts`,
            line: index + 1,
            severity: 'medium' as const,
            ruleId: 'TLP-GENERATED'
          }))
        ]
      }),
      publishResult: async (work, _repository, summary) => {
        published.push({
          work,
          revision: summary.revision,
          status: summary.status,
          findingCount: summary.findingCount,
          annotations: [...(summary.annotations ?? [])]
        });
      },
      audit: (entry) => audit.push({ ...entry })
    });
    roots.push(() => service.close());

    expect(
      (await request(service, 'push', 'publish-summary', payload())).status
    ).toBe(202);
    await viWaitFor(() => expect(published).toHaveLength(1));
    expect(published[0]).toMatchObject({
      work: { repositoryId: 123, revision: 'a'.repeat(40) },
      revision: 'a'.repeat(40),
      status: 'complete',
      findingCount: 60
    });
    expect(published[0]?.annotations).toHaveLength(50);
    expect(published[0]?.annotations).toContainEqual(
      expect.objectContaining({
        path: 'a/a.ts',
        line: 7,
        ruleId: 'TLP-TEST-001'
      })
    );
    expect(JSON.stringify(published[0]?.annotations)).not.toContain(
      'outside.ts'
    );
    expect(JSON.stringify(published[0]?.annotations)).not.toContain('ghp_');
    expect(JSON.stringify(published)).not.toContain('private path');
    await viWaitFor(() =>
      expect(audit.some((entry) => entry.event === 'check-run-published')).toBe(
        true
      )
    );
  });

  it('scans only the exact provisioned clean commit through the shared scorecard', async () => {
    const root = makeRepo();
    write(
      root,
      'package.json',
      JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: {} })
    );
    git(root, 'add', 'package.json');
    git(root, 'commit', '-qm', 'add package manifest');
    const revision = git(root, 'rev-parse', 'HEAD').trim();
    const observed = await runGit(['rev-parse', '--verify', 'HEAD^{commit}'], {
      cwd: root,
      timeoutMs: 5_000,
      maxBuffer: 4_096
    });
    expect(observed.stdout.toString('utf8').trim()).toBe(revision);
    const scanner = createGitHubAppScorecardScanner({ offline: true });
    const repository = {
      name: 'acme/service',
      installationId: 42,
      repositoryId: 123,
      root
    };
    const work: GitHubAppScanWork = {
      kind: 'push',
      installationId: 42,
      repository: 'acme/service',
      repositoryId: 123,
      revision,
      deliveryId: 'delivery-exact'
    };
    const exact = await scanner(work, repository, new AbortController().signal);
    expect(exact.status, JSON.stringify(exact)).toBe('complete');
    expect(exact.snapshotId).toMatch(/^[a-f0-9]{64}$/u);

    const mismatched = await scanner(
      { ...work, revision: 'b'.repeat(40) },
      repository,
      new AbortController().signal
    );
    expect(mismatched).toMatchObject({
      status: 'incomplete',
      reason: 'requested-revision-not-provisioned'
    });

    write(root, 'uncommitted.ts', 'export const changed = true;\n');
    const dirty = await scanner(work, repository, new AbortController().signal);
    expect(dirty).toMatchObject({
      status: 'incomplete',
      reason: 'repository-worktree-not-clean'
    });
  });
});

async function viWaitFor(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      assertion();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
  }
  assertion();
}
