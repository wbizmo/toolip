import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { profileProject } from '../src/core/profile-project.js';

describe('profileProject', () => {
  it('detects TypeScript, Fastify, Prisma, and npm projects', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-profile-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          dependencies: {
            fastify: '^5.0.0',
            '@prisma/client': '^6.0.0'
          },
          devDependencies: {
            typescript: '^5.0.0'
          }
        })
      );

      await writeFile(path.join(root, 'package-lock.json'), '{}');

      const profile = await profileProject(root);

      expect(profile.packageManager).toBe('npm');
      expect(profile.hasTypeScript).toBe(true);
      expect(profile.hasFastify).toBe(true);
      expect(profile.hasPrisma).toBe(true);
      expect(profile.detected).toContain('TypeScript');
      expect(profile.detected).toContain('Fastify');
      expect(profile.detected).toContain('Prisma');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
