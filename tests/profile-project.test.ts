import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { profileProject } from '../src/core/profile-project.js';

describe('profileProject', () => {
  it('detects TypeScript, Fastify, Prisma, scripts, metadata, and npm projects', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-profile-'));

    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({
          name: 'sample-api',
          version: '1.2.3',
          description: 'A sample Fastify API',
          scripts: {
            test: 'vitest run',
            build: 'tsc'
          },
          dependencies: {
            fastify: '^5.0.0',
            '@prisma/client': '^6.0.0'
          },
          devDependencies: {
            typescript: '^5.0.0',
            vitest: '^3.0.0'
          }
        })
      );

      await writeFile(path.join(root, 'package-lock.json'), '{}');
      await writeFile(path.join(root, 'tsconfig.json'), '{}');
      await writeFile(path.join(root, 'index.ts'), 'export const app = true;');

      const profile = await profileProject(root);

      expect(profile.name).toBe('sample-api');
      expect(profile.version).toBe('1.2.3');
      expect(profile.description).toBe('A sample Fastify API');
      expect(profile.packageManager).toBe('npm');
      expect(profile.hasTypeScript).toBe(true);
      expect(profile.hasFastify).toBe(true);
      expect(profile.hasPrisma).toBe(true);
      expect(profile.hasVitest).toBe(true);
      expect(profile.detected).toContain('TypeScript');
      expect(profile.detected).toContain('Fastify');
      expect(profile.detected).toContain('Prisma');
      expect(profile.detected).toContain('Vitest');
      expect(profile.packageScripts).toContain('test');
      expect(profile.packageScripts).toContain('build');
      expect(profile.languages.TypeScript).toBeGreaterThanOrEqual(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('detects GitHub Actions and Docker signals', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-profile-'));

    try {
      await mkdir(path.join(root, '.github', 'workflows'), { recursive: true });
      await writeFile(path.join(root, 'Dockerfile'), 'FROM node:22-alpine');
      await writeFile(path.join(root, '.github', 'workflows', 'ci.yml'), 'name: CI');

      const profile = await profileProject(root);

      expect(profile.hasDocker).toBe(true);
      expect(profile.hasGitHubActions).toBe(true);
      expect(profile.detected).toContain('Docker');
      expect(profile.detected).toContain('GitHub Actions');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
