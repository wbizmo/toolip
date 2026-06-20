import { access, readFile } from 'node:fs/promises';
import path from 'node:path';

export type ProjectProfile = {
  root: string;
  packageManager: 'npm' | 'pnpm' | 'yarn' | 'unknown';
  hasTypeScript: boolean;
  hasReact: boolean;
  hasExpress: boolean;
  hasFastify: boolean;
  hasPrisma: boolean;
  hasDocker: boolean;
  detected: string[];
};

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readPackageJson(root: string): Promise<Record<string, unknown>> {
  const packagePath = path.join(root, 'package.json');

  if (!(await fileExists(packagePath))) {
    return {};
  }

  const raw = await readFile(packagePath, 'utf8');
  return JSON.parse(raw) as Record<string, unknown>;
}

function dependencyNames(packageJson: Record<string, unknown>): string[] {
  const dependencies = packageJson.dependencies as Record<string, string> | undefined;
  const devDependencies = packageJson.devDependencies as Record<string, string> | undefined;

  return [
    ...Object.keys(dependencies ?? {}),
    ...Object.keys(devDependencies ?? {})
  ];
}

async function detectPackageManager(root: string): Promise<ProjectProfile['packageManager']> {
  if (await fileExists(path.join(root, 'pnpm-lock.yaml'))) return 'pnpm';
  if (await fileExists(path.join(root, 'yarn.lock'))) return 'yarn';
  if (await fileExists(path.join(root, 'package-lock.json'))) return 'npm';
  return 'unknown';
}

export async function profileProject(root: string): Promise<ProjectProfile> {
  const absoluteRoot = path.resolve(root);
  const packageJson = await readPackageJson(absoluteRoot);
  const deps = dependencyNames(packageJson);
  const packageManager = await detectPackageManager(absoluteRoot);

  const profile: ProjectProfile = {
    root: absoluteRoot,
    packageManager,
    hasTypeScript: deps.includes('typescript') || await fileExists(path.join(absoluteRoot, 'tsconfig.json')),
    hasReact: deps.includes('react'),
    hasExpress: deps.includes('express'),
    hasFastify: deps.includes('fastify'),
    hasPrisma: deps.includes('prisma') || deps.includes('@prisma/client'),
    hasDocker: await fileExists(path.join(absoluteRoot, 'Dockerfile')) || await fileExists(path.join(absoluteRoot, 'docker-compose.yml')),
    detected: []
  };

  if (profile.hasTypeScript) profile.detected.push('TypeScript');
  if (profile.hasReact) profile.detected.push('React');
  if (profile.hasExpress) profile.detected.push('Express');
  if (profile.hasFastify) profile.detected.push('Fastify');
  if (profile.hasPrisma) profile.detected.push('Prisma');
  if (profile.hasDocker) profile.detected.push('Docker');

  return profile;
}
