import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

async function git(
  root: string,
  args: string[]
): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync(
      'git',
      args,
      {
        cwd: root,
        encoding: 'utf8'
      }
    );

    return stdout.trim() || undefined;
  } catch {
    return undefined;
  }
}

export async function readGitMetadata(
  root: string
): Promise<{
  branch?: string;
  commit?: string;
  dirty?: boolean;
}> {
  const branch = await git(root, [
    'branch',
    '--show-current'
  ]);

  const commit = await git(root, [
    'rev-parse',
    'HEAD'
  ]);

  const status = await git(root, [
    'status',
    '--porcelain'
  ]);

  return {
    branch,
    commit,
    dirty:
      status === undefined
        ? undefined
        : status.length > 0
  };
}
