import { access, lstat } from 'node:fs/promises';
import path from 'node:path';
import { walkProjectFiles, type ProjectFile } from './file-walker.js';
import { snapshotOf, TextFileReader } from './text-file-reader.js';
import { ToolipError } from '../errors/toolip-error.js';
import {
  detectPackageManager,
  type PackageManager
} from './package-manager.js';

const manifestBudget = {
  maxFiles: 1,
  maxFileBytes: 16 * 1024 * 1024,
  maxTotalBytes: 16 * 1024 * 1024
};

export type ProjectProfile = {
  root: string;
  name: string;
  version: string;
  description: string;
  packageManager: PackageManager;
  hasPHP: boolean;
  hasLaravel: boolean;
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

/** Checks whether a project capability path exists without reading its content. */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/** Reads the root manifest through the bounded, snapshot-checked reader. */
async function readPackageJson(
  root: string,
  files: readonly ProjectFile[],
  snapshotContents?: ReadonlyMap<string, string>
): Promise<Record<string, unknown>> {
  if (snapshotContents) {
    const snapshotManifest = snapshotContents.get('package.json');
    return snapshotManifest === undefined
      ? {}
      : (JSON.parse(snapshotManifest) as Record<string, unknown>);
  }
  let manifest = files.find((file) => file.relativePath === 'package.json');
  if (!manifest) {
    const absolutePath = path.join(root, 'package.json');
    try {
      const stat = await lstat(absolutePath, { bigint: true });
      if (!stat.isFile()) {
        throw new ToolipError(
          'Project manifest changed or could not be read safely.',
          { code: 'SCAN_DISCOVERY_INCOMPLETE' }
        );
      }
      manifest = {
        absolutePath,
        relativePath: 'package.json',
        extension: 'json',
        snapshot: snapshotOf(stat)
      };
    } catch (error) {
      if (
        error !== null &&
        typeof error === 'object' &&
        'code' in error &&
        error.code === 'ENOENT'
      ) {
        return {};
      }
      if (error instanceof ToolipError) throw error;
      throw new ToolipError('Project manifest could not be inspected safely.', {
        code: 'SCAN_DISCOVERY_INCOMPLETE'
      });
    }
  }
  const result = await new TextFileReader(manifestBudget, { root }).read(
    manifest.absolutePath,
    undefined,
    manifest.snapshot
  );
  if (result.status !== 'ok') {
    throw new ToolipError(
      'Project manifest changed or could not be read safely.',
      {
        code: 'SCAN_DISCOVERY_INCOMPLETE'
      }
    );
  }
  return JSON.parse(result.content) as Record<string, unknown>;
}

async function readComposerJson(
  root: string,
  files: readonly ProjectFile[],
  snapshotContents?: ReadonlyMap<string, string>
): Promise<Record<string, unknown>> {
  if (snapshotContents) {
    const content = snapshotContents.get('composer.json');
    return content === undefined
      ? {}
      : (JSON.parse(content) as Record<string, unknown>);
  }
  let manifest = files.find((file) => file.relativePath === 'composer.json');
  if (!manifest) {
    const absolutePath = path.join(root, 'composer.json');
    try {
      const stat = await lstat(absolutePath, { bigint: true });
      if (!stat.isFile()) {
        throw new ToolipError(
          'Composer manifest changed or could not be read safely.',
          { code: 'SCAN_DISCOVERY_INCOMPLETE' }
        );
      }
      manifest = {
        absolutePath,
        relativePath: 'composer.json',
        extension: 'json',
        snapshot: snapshotOf(stat)
      };
    } catch (error) {
      if (
        error !== null &&
        typeof error === 'object' &&
        'code' in error &&
        error.code === 'ENOENT'
      )
        return {};
      if (error instanceof ToolipError) throw error;
      throw new ToolipError(
        'Composer manifest could not be inspected safely.',
        {
          code: 'SCAN_DISCOVERY_INCOMPLETE'
        }
      );
    }
  }
  const result = await new TextFileReader(manifestBudget, { root }).read(
    manifest.absolutePath,
    undefined,
    manifest.snapshot
  );
  if (result.status !== 'ok')
    throw new ToolipError(
      'Composer manifest changed or could not be read safely.',
      { code: 'SCAN_DISCOVERY_INCOMPLETE' }
    );
  return JSON.parse(result.content) as Record<string, unknown>;
}

/** Lists declared production and development dependency names. */
function dependencyNames(packageJson: Record<string, unknown>): string[] {
  const dependencies = packageJson.dependencies as
    Record<string, string> | undefined;
  const devDependencies = packageJson.devDependencies as
    Record<string, string> | undefined;

  return [
    ...Object.keys(dependencies ?? {}),
    ...Object.keys(devDependencies ?? {})
  ];
}

/** Returns lifecycle and project script names declared in the manifest. */
function packageScripts(packageJson: Record<string, unknown>): string[] {
  const scripts = packageJson.scripts as Record<string, string> | undefined;
  return Object.keys(scripts ?? {});
}

/** Counts recognized source and configuration languages in discovered files. */
function summarizeLanguages(
  files: readonly ProjectFile[]
): Record<string, number> {
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
    dockerfile: 'Docker',
    php: 'PHP'
  };

  return files.reduce<Record<string, number>>((summary, file) => {
    const extension = file.extension || file.relativePath.toLowerCase();
    const language = languageMap[extension] ?? extension.toUpperCase();

    summary[language] = (summary[language] ?? 0) + 1;
    return summary;
  }, {});
}

/** Builds the project summary used to select and configure analyzers. */
export async function profileProject(
  root: string,
  discoveredFiles?: readonly ProjectFile[],
  options: { snapshotContents?: ReadonlyMap<string, string> } = {}
): Promise<ProjectProfile> {
  const absoluteRoot = path.resolve(root);
  const files = discoveredFiles ?? (await walkProjectFiles(absoluteRoot));
  const packageJson = await readPackageJson(
    absoluteRoot,
    files,
    options.snapshotContents
  );
  const composerJson = await readComposerJson(
    absoluteRoot,
    files,
    options.snapshotContents
  );
  const deps = dependencyNames(packageJson);
  const composerDependencies = new Set(
    [
      ...Object.keys(
        (composerJson.require as Record<string, unknown> | undefined) ?? {}
      ),
      ...Object.keys(
        (composerJson['require-dev'] as Record<string, unknown> | undefined) ??
          {}
      )
    ].map((name) => name.toLowerCase())
  );
  const scripts = packageScripts(packageJson);
  const snapshotPaths = options.snapshotContents
    ? new Set(files.map((file) => file.relativePath))
    : undefined;
  const hasFile = async (relativePath: string): Promise<boolean> =>
    snapshotPaths
      ? snapshotPaths.has(relativePath)
      : fileExists(path.join(absoluteRoot, relativePath));
  let packageManager: PackageManager;
  if (snapshotPaths) {
    const managers: Array<[PackageManager, string]> = [
      ['pnpm', 'pnpm-lock.yaml'],
      ['yarn', 'yarn.lock'],
      ['npm', 'package-lock.json']
    ];
    const detected = managers.filter(([, lockfile]) =>
      snapshotPaths.has(lockfile)
    );
    packageManager =
      detected.length === 1 ? (detected[0]?.[0] ?? 'unknown') : 'unknown';
  } else {
    packageManager = await detectPackageManager(absoluteRoot);
  }

  const profile: ProjectProfile = {
    root: absoluteRoot,
    name: typeof packageJson.name === 'string' ? packageJson.name : 'unknown',
    version:
      typeof packageJson.version === 'string' ? packageJson.version : 'unknown',
    description:
      typeof packageJson.description === 'string'
        ? packageJson.description
        : '',
    packageManager,
    hasPHP:
      files.some((file) => file.extension === 'php') ||
      (await hasFile('composer.json')) ||
      (await hasFile('composer.lock')),
    hasLaravel:
      composerDependencies.has('laravel/framework') ||
      ((await hasFile('artisan')) && (await hasFile('bootstrap/app.php'))),
    hasTypeScript:
      deps.includes('typescript') || (await hasFile('tsconfig.json')),
    hasJavaScript: files.some((file) => ['js', 'jsx'].includes(file.extension)),
    hasReact: deps.includes('react'),
    hasExpress: deps.includes('express'),
    hasFastify: deps.includes('fastify'),
    hasPrisma: deps.includes('prisma') || deps.includes('@prisma/client'),
    hasDocker:
      (await hasFile('Dockerfile')) || (await hasFile('docker-compose.yml')),
    hasVitest: deps.includes('vitest'),
    hasJest: deps.includes('jest'),
    hasESLint: deps.includes('eslint'),
    hasPrettier: deps.includes('prettier'),
    hasGitHubActions: snapshotPaths
      ? [...snapshotPaths].some((name) => name.startsWith('.github/workflows/'))
      : await fileExists(path.join(absoluteRoot, '.github', 'workflows')),
    detected: [],
    languages: summarizeLanguages(files),
    packageScripts: scripts
  };

  if (profile.hasTypeScript) profile.detected.push('TypeScript');
  if (profile.hasPHP) profile.detected.push('PHP');
  if (profile.hasLaravel) profile.detected.push('Laravel');
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
