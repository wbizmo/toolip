import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadGitHubAppConfiguration } from '../../src/commands/github-app.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function config(contents: unknown): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-github-app-'));
  roots.push(root);
  const file = path.join(root, 'app.json');
  await writeFile(file, JSON.stringify(contents));
  return file;
}

describe('GitHub App local configuration', () => {
  it('loads a strict absolute-path repository allowlist', async () => {
    const file = await config({
      version: 1,
      repositories: [
        { name: 'Acme/Service', installationId: 42, repositoryId: 123, root: path.resolve('/tmp/service') }
      ]
    });
    await expect(loadGitHubAppConfiguration(file)).resolves.toMatchObject({
      version: 1,
      repositories: [{ name: 'Acme/Service', installationId: 42, repositoryId: 123 }]
    });
  });

  it('rejects unknown keys, relative roots, and duplicate repository identities', async () => {
    await expect(
      loadGitHubAppConfiguration(
        await config({ version: 1, repositories: [], allowAll: true })
      )
    ).rejects.toThrow('supported schema');
    await expect(
      loadGitHubAppConfiguration(
        await config({
          version: 1,
          repositories: [
            { name: 'acme/service', installationId: 42, repositoryId: 123, root: 'relative/path' }
          ]
        })
      )
    ).rejects.toThrow('supported schema');
    await expect(
      loadGitHubAppConfiguration(
        await config({
          version: 1,
          repositories: [
            { name: 'acme/service', installationId: 42, repositoryId: 123, root: '/tmp/one' },
            { name: 'ACME/SERVICE', installationId: 42, repositoryId: 123, root: '/tmp/two' }
          ]
        })
      )
    ).rejects.toThrow('duplicate repositories');
  });

  it('rejects oversized input before parsing', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-github-app-large-'));
    roots.push(root);
    const file = path.join(root, 'large.json');
    await writeFile(file, ' '.repeat(256 * 1024 + 1));
    await expect(loadGitHubAppConfiguration(file)).rejects.toThrow(
      'bounded regular file'
    );
  });
});
