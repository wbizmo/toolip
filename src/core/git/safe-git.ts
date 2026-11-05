import { execFile } from 'node:child_process';
import { ToolipError } from '../../errors/toolip-error.js';

export type GitRunOptions = {
  cwd: string;
  /** Wall-clock limit for the subprocess. Default 30 s. */
  timeoutMs?: number;
  /** Maximum captured stdout/stderr bytes. Default 16 MiB. */
  maxBuffer?: number;
  signal?: AbortSignal;
  /** Written to stdin then closed (for `--stdin` style commands). */
  input?: string;
};

export type GitResult = {
  code: number;
  stdout: Buffer;
  stderr: string;
};

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BUFFER = 16 * 1024 * 1024;

/**
 * Runs git with an argument vector (never a shell), bounded time and output.
 * Resolves with the exit code instead of throwing for ordinary non-zero exits,
 * so callers decide whether that is an error. Spawn failures, timeouts,
 * aborts and buffer overflows reject with a typed ToolipError.
 *
 * Environment is inherited on purpose: inside a hook, Git exports GIT_DIR and
 * GIT_INDEX_FILE (a temporary index for `git commit <paths>`), and reading the
 * real index requires honoring them. Prompts are disabled.
 */
export function runGit(
  args: readonly string[],
  options: GitRunOptions
): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'git',
      [...args],
      {
        cwd: options.cwd,
        encoding: 'buffer',
        timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
        signal: options.signal,
        windowsHide: true,
        env: {
          ...process.env,
          GIT_TERMINAL_PROMPT: '0',
          GIT_OPTIONAL_LOCKS: '0'
        }
      },
      (error, stdout, stderr) => {
        if (!error) {
          resolve({ code: 0, stdout, stderr: stderr.toString('utf8') });
          return;
        }

        const failure = error as NodeJS.ErrnoException & {
          killed?: boolean;
          signal?: string | null;
          code?: number | string;
        };

        if (typeof failure.code === 'number') {
          resolve({
            code: failure.code,
            stdout,
            stderr: stderr.toString('utf8')
          });
          return;
        }

        reject(
          new ToolipError(
            failure.code === 'ENOENT'
              ? 'Git is required but was not found on PATH.'
              : failure.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
                ? 'Git output exceeded the configured size limit.'
                : failure.name === 'AbortError'
                  ? 'Git command was cancelled.'
                  : failure.killed
                    ? 'Git command timed out.'
                    : `Git command could not be run (${failure.code ?? 'unknown'}).`,
            { code: 'GIT_COMMAND_FAILED', exitCode: 1 }
          )
        );
      }
    );
    child.stdin?.on('error', () => undefined);
    child.stdin?.end(options.input);
  });
}

/** Like runGit but throws a typed error on any non-zero exit. */
export async function runGitChecked(
  args: readonly string[],
  options: GitRunOptions,
  errorCode = 'GIT_COMMAND_FAILED'
): Promise<Buffer> {
  const result = await runGit(args, options);
  if (result.code !== 0) {
    throw new ToolipError(
      `Git ${args[0] ?? ''} failed (exit ${result.code}): ${firstLine(result.stderr)}`,
      { code: errorCode, exitCode: 1 }
    );
  }
  return result.stdout;
}

function firstLine(text: string): string {
  const line = text.split(/\r?\n/u).find((entry) => entry.trim().length > 0);
  return (line ?? 'no diagnostic output').slice(0, 200);
}
