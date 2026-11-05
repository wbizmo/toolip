import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import { ToolipError } from '../errors/toolip-error.js';
import { runGit } from './git/safe-git.js';

const managedStart = '# >>> toolip managed pre-commit >>>';
const managedEnd = '# <<< toolip managed pre-commit <<<';

/**
 * The hook never downloads anything: it uses the project-local (lockfile
 * pinned) Toolip, else a Toolip on PATH, else fails closed with remediation.
 */
const managedBlock = `${managedStart}
echo "Running Toolip pre-commit checks..."
if [ -x "./node_modules/.bin/toolip" ]; then
  toolip_bin="./node_modules/.bin/toolip"
elif command -v toolip >/dev/null 2>&1; then
  toolip_bin="$(command -v toolip)"
else
  echo "Toolip pre-commit hook could not find Toolip." >&2
  echo "Install it in this project (npm install --save-dev toolip) or globally (npm install --global toolip). The hook never downloads packages." >&2
  exit 1
fi
"$toolip_bin" pre-commit --path .
toolip_status=$?
if [ "$toolip_status" -ne 0 ]; then
  exit "$toolip_status"
fi
${managedEnd}`;

export type HookInstallResult = {
  hookPath: string;
  hooksDir: string;
  source: 'core.hooksPath' | 'git-path';
  warnings: string[];
};

/** Back-compatible wrapper returning only the installed hook path. */
export async function installPreCommitHook(root: string): Promise<string> {
  return (await installPreCommitHookDetailed(root)).hookPath;
}

/**
 * Installs (or updates) exactly one Toolip block in Git's *effective*
 * pre-commit hook: the directory Git will really execute, honoring
 * `core.hooksPath` and linked worktrees. The block is placed immediately after
 * the shebang so an earlier `exit`/`exec` in the user's logic cannot silently
 * bypass it; re-running removes any existing block and re-inserts it there
 * (idempotent). User content is preserved and the file is replaced atomically.
 */
export async function installPreCommitHookDetailed(
  root: string
): Promise<HookInstallResult> {
  const warnings: string[] = [];
  const { hooksDir: resolvedDir, source } = await resolveHooksDir(root);

  // Husky v9 generates `.husky/_/*`; user hooks live one level up.
  let hooksDir = resolvedDir;
  if (
    path.basename(hooksDir) === '_' &&
    path.basename(path.dirname(hooksDir)) === '.husky'
  ) {
    await assertHuskyDispatcher(resolvedDir);
    hooksDir = path.dirname(hooksDir);
    warnings.push(
      'core.hooksPath points at Husky generated files; installing into .husky/pre-commit instead.'
    );
  }

  const hookPath = path.join(hooksDir, 'pre-commit');
  await mkdir(hooksDir, { recursive: true });

  let existing = '';
  let mode = 0o755;
  try {
    existing = await readFile(hookPath, 'utf8');
    mode = ((await stat(hookPath)).mode & 0o777) | 0o111;
  } catch (error) {
    if (errorCode(error) !== 'ENOENT') throw error;
  }

  assertShellHook(existing);
  warnings.push(...detectManagers(existing, hooksDir));

  const content = placeManagedBlock(existing);
  const temporary = `${hookPath}.toolip-${process.pid}.tmp`;
  try {
    await writeFile(temporary, content, { encoding: 'utf8', mode });
    await chmod(temporary, mode);
    await rename(temporary, hookPath);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }

  return { hookPath, hooksDir, source, warnings };
}

/**
 * Husky v9 points core.hooksPath at generated files in `.husky/_`; its
 * dispatcher there runs the user-editable `.husky/<hook>`. Installing into the
 * user file is useless unless the dispatcher exists and can run, so verify it
 * and fail with remediation instead of reporting a hook that will never fire.
 */
async function assertHuskyDispatcher(generatedDir: string): Promise<void> {
  const dispatcher = path.join(generatedDir, 'pre-commit');
  const helper = path.join(generatedDir, 'h');
  let usable = false;

  try {
    const [info] = await Promise.all([stat(dispatcher), stat(helper)]);
    usable =
      info.isFile() &&
      (process.platform === 'win32' || (info.mode & 0o111) !== 0);
  } catch {
    usable = false;
  }

  if (!usable) {
    throw new ToolipError(
      'core.hooksPath points at Husky generated files, but .husky/_/pre-commit (and its "h" helper) is missing or not executable, so a hook added to .husky/pre-commit would never run. Run Husky\'s install step (for example `npm run prepare`) to regenerate it, then retry; Toolip did not modify anything.',
      { code: 'HOOK_HUSKY_DISPATCHER_MISSING', exitCode: 1 }
    );
  }
}

async function resolveHooksDir(
  root: string
): Promise<{ hooksDir: string; source: 'core.hooksPath' | 'git-path' }> {
  const cwd = path.resolve(root);
  const top = await runGit(['rev-parse', '--show-toplevel'], {
    cwd,
    timeoutMs: 10_000,
    maxBuffer: 64 * 1024
  });

  if (top.code !== 0) {
    throw new ToolipError(
      'Installing a Git hook requires a Git repository or worktree.',
      { code: 'HOOK_GIT_REQUIRED', exitCode: 1 }
    );
  }

  const topLevel = top.stdout.toString('utf8').trim();

  const configured = await runGit(
    ['config', '--path', '--get', 'core.hooksPath'],
    {
      cwd,
      timeoutMs: 10_000,
      maxBuffer: 64 * 1024
    }
  );
  const hooksPath = configured.stdout.toString('utf8').trim();
  if (configured.code === 0 && hooksPath.length > 0) {
    // Relative values are relative to the directory hooks run in (the top level).
    return {
      hooksDir: path.resolve(topLevel, hooksPath),
      source: 'core.hooksPath'
    };
  }

  const gitPath = await runGit(['rev-parse', '--git-path', 'hooks'], {
    cwd,
    timeoutMs: 10_000,
    maxBuffer: 64 * 1024
  });
  if (gitPath.code !== 0) {
    throw new ToolipError('Could not determine the Git hooks directory.', {
      code: 'HOOK_GIT_REQUIRED',
      exitCode: 1
    });
  }

  return {
    hooksDir: path.resolve(cwd, gitPath.stdout.toString('utf8').trim()),
    source: 'git-path'
  };
}

function assertShellHook(existing: string): void {
  if (!existing.startsWith('#!')) return;
  const firstLine = existing.split('\n', 1)[0] ?? '';
  const interpreter = firstLine
    .replace(/^#!\s*/, '')
    .split(/\s+/)
    .map((part) => path.posix.basename(part))
    .filter(
      (part) => part !== '' && part !== 'env' && !part.startsWith('-')
    )[0];

  if (!interpreter || !/^(?:ba|da|z|k|a)?sh$/.test(interpreter)) {
    throw new ToolipError(
      `The existing pre-commit hook uses "${firstLine.trim()}", which is not a POSIX shell. Add "toolip pre-commit --path ." to it manually; Toolip will not rewrite a non-shell hook.`,
      { code: 'HOOK_UNSUPPORTED_INTERPRETER', exitCode: 1 }
    );
  }
}

function detectManagers(existing: string, hooksDir: string): string[] {
  const warnings: string[] = [];
  const haystack = `${existing}\n${hooksDir}`.toLowerCase();
  for (const manager of ['husky', 'lefthook', 'simple-git-hooks']) {
    if (haystack.includes(manager)) {
      warnings.push(
        `This hook appears to be managed by ${manager}; regenerating it can remove the Toolip block. Prefer adding "toolip pre-commit --path ." to that tool's pre-commit configuration.`
      );
    }
  }
  return warnings;
}

/** Removes any managed block, then inserts one right after the shebang. */
export function placeManagedBlock(existing: string): string {
  const withoutBlock = removeManagedBlock(existing);
  const lines = withoutBlock.length === 0 ? [] : withoutBlock.split('\n');
  const hasShebang = (lines[0] ?? '').startsWith('#!');
  const head = hasShebang ? [lines[0] as string] : ['#!/bin/sh'];
  const rest = hasShebang ? lines.slice(1) : lines;
  const body = rest.join('\n').replace(/^\n+/, '').replace(/\s*$/, '');

  return `${head.join('\n')}\n${managedBlock}\n${body.length > 0 ? `\n${body}\n` : ''}`;
}

function removeManagedBlock(existing: string): string {
  const starts = existing.split(managedStart).length - 1;
  const ends = existing.split(managedEnd).length - 1;
  const start = existing.indexOf(managedStart);
  const end = existing.indexOf(managedEnd);

  if (starts !== ends || starts > 1 || (starts === 1 && end < start)) {
    throw new ToolipError(
      starts > 1
        ? 'Existing pre-commit hook contains more than one Toolip-managed block. Repair it manually before reinstalling.'
        : 'Existing pre-commit hook contains an incomplete Toolip-managed block. Repair it manually before reinstalling.',
      { code: 'HOOK_MANAGED_BLOCK_CORRUPT', exitCode: 1 }
    );
  }

  if (starts === 0) return existing;
  return `${existing.slice(0, start)}${existing.slice(end + managedEnd.length)}`.replace(
    /\n{3,}/g,
    '\n\n'
  );
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
