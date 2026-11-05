import { execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  realpathSync
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const cleanups: string[] = [];

/** Environment for Git subprocesses that is isolated from the developer's config. */
let emptyConfig: string | undefined;
/** An empty file used as the global/system config (os.devNull is unusable on Windows). */
function emptyConfigFile(): string {
  if (!emptyConfig) {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'toolip-gitcfg-'));
    cleanups.push(dir);
    emptyConfig = path.join(dir, 'empty.gitconfig');
    writeFileSync(emptyConfig, '');
  }
  return emptyConfig;
}

export function gitEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...extra };
  for (const key of Object.keys(env)) {
    if (key.startsWith('GIT_') && key !== 'GIT_TERMINAL_PROMPT')
      delete env[key];
  }
  return {
    ...env,
    ...extra,
    GIT_CONFIG_GLOBAL: emptyConfigFile(),
    GIT_CONFIG_SYSTEM: emptyConfigFile(),
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Toolip Test',
    GIT_AUTHOR_EMAIL: 'toolip@example.test',
    GIT_COMMITTER_NAME: 'Toolip Test',
    GIT_COMMITTER_EMAIL: 'toolip@example.test'
  };
}

export function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', env: gitEnv() });
}

export function tempDir(prefix = 'toolip-git-'): string {
  const dir = realpathSync.native(mkdtempSync(path.join(os.tmpdir(), prefix)));
  cleanups.push(dir);
  return dir;
}

/** Creates an initialized repository with one commit (main). */
export function makeRepo(): string {
  const root = tempDir();
  git(root, 'init', '-q', '-b', 'main');
  git(root, 'config', 'commit.gpgsign', 'false');
  git(root, 'config', 'core.autocrlf', 'false');
  write(root, 'README.md', '# fixture\n');
  git(root, 'add', '.');
  git(root, 'commit', '-q', '-m', 'initial');
  return root;
}

export function write(root: string, file: string, content: string): void {
  const target = path.join(root, file);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, content);
}

export function cleanupRepos(): void {
  for (const dir of cleanups.splice(0)) {
    // Windows can briefly hold the cwd of a just-exited Git process.
    rmSync(dir, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100
    });
  }
  emptyConfig = undefined;
}

/** A synthetic credential-shaped line assembled at runtime so no literal secret sits in the repo. */
export function fakeSecretLine(label: string): string {
  return `const password = "${label}-supersecretpassword";\n`;
}
