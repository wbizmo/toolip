import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { walkProjectFiles } from './file-walker.js';

export type ProjectProfile = {
  root: string;
  name: string;
  version: string;
  description: string;
  packageManager: 'npm' | 'pnpm' | 'yarn' | 'unknown';
  hasTypeScript: boolean;
  hasJavaScript: boolean;
  hasReact: boolean;
  hasExpress: boolean;
  hasFastify: boolean;
  hasPrisma: boolean;
  hasDocker: boolean;
  hasVitest: boolean;
  hasJest: boolean;
  hasESLint: boolean;
  hasPrettier: boolean;
  hasGitHubActions: boolean;
  detected: string[];
  languages: Record<string, number>;
  packageScripts: string[];
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

function packageScripts(packageJson: Record<string, unknown>): string[] {
  const scripts = packageJson.scripts as Record<string, string> | undefined;
  return Object.keys(scripts ?? {});
}

async function detectPackageManager(root: string): Promise<ProjectProfile['packageManager']> {
  if (await fileExists(path.join(root, 'pnpm-lock.yaml'))) return 'pnpm';
  if (await fileExists(path.join(root, 'yarn.lock'))) return 'yarn';
  if (await fileExists(path.join(root, 'package-lock.json'))) return 'npm';
  return 'unknown';
}

function summarizeLanguages(files: Awaited<ReturnType<typeof walkProjectFiles>>): Record<string, number> {
  const languageMap: Record<string, string> = {
    ts: 'TypeScript',
    tsx: 'TypeScript React',
    js: 'JavaScript',
    jsx: 'JavaScript React',
    json: 'JSON',
    yml: 'YAML',
    yaml: 'YAML',
    md: 'Markdown',
    css: 'CSS',
    html: 'HTML',
    env: 'Environment',
    dockerfile: 'Docker'
  };

  return files.reduce<Record<string, number>>((summary, file) => {
    const extension = file.extension || file.relativePath.toLowerCase();
    const language = languageMap[extension] ?? extension.toUpperCase();

    summary[language] = (summary[language] ?? 0) + 1;
    return summary;
  }, {});
}

export async function profileProject(root: string): Promise<ProjectProfile> {
  const absoluteRoot = path.resolve(root);
  const packageJson = await readPackageJson(absoluteRoot);
  const deps = dependencyNames(packageJson);
  const scripts = packageScripts(packageJson);
  const files = await walkProjectFiles(absoluteRoot);

  const packageManager = await detectPackageManager(absoluteRoot);

  const profile: ProjectProfile = {
    root: absoluteRoot,
    name: typeof packageJson.name === 'string' ? packageJson.name : 'unknown',
    version: typeof packageJson.version === 'string' ? packageJson.version : 'unknown',
    description: typeof packageJson.description === 'string' ? packageJson.description : '',
    packageManager,
    hasTypeScript: deps.includes('typescript') || await fileExists(path.join(absoluteRoot, 'tsconfig.json')),
    hasJavaScript: files.some((file) => ['js', 'jsx'].includes(file.extension)),
    hasReact: deps.includes('react'),
    hasExpress: deps.includes('express'),
    hasFastify: deps.includes('fastify'),
    hasPrisma: deps.includes('prisma') || deps.includes('@prisma/client'),
    hasDocker: await fileExists(path.join(absoluteRoot, 'Dockerfile')) || await fileExists(path.join(absoluteRoot, 'docker-compose.yml')),
    hasVitest: deps.includes('vitest'),
    hasJest: deps.includes('jest'),
    hasESLint: deps.includes('eslint'),
    hasPrettier: deps.includes('prettier'),
    hasGitHubActions: await fileExists(path.join(absoluteRoot, '.github', 'workflows')),
    detected: [],
    languages: summarizeLanguages(files),
    packageScripts: scripts
  };

  if (profile.hasTypeScript) profile.detected.push('TypeScript');
  if (profile.hasJavaScript) profile.detected.push('JavaScript');
  if (profile.hasReact) profile.detected.push('React');
  if (profile.hasExpress) profile.detected.push('Express');
  if (profile.hasFastify) profile.detected.push('Fastify');
  if (profile.hasPrisma) profile.detected.push('Prisma');
  if (profile.hasDocker) profile.detected.push('Docker');
  if (profile.hasVitest) profile.detected.push('Vitest');
  if (profile.hasJest) profile.detected.push('Jest');
  if (profile.hasESLint) profile.detected.push('ESLint');
  if (profile.hasPrettier) profile.detected.push('Prettier');
  if (profile.hasGitHubActions) profile.detected.push('GitHub Actions');

  return profile;
}
