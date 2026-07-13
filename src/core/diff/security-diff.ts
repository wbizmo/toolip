import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export type SecurityDiffResult = {
  base: string;
  head: string;
  files: string[];
  packageManifestChanged: boolean;
  lockfileChanged: boolean;
  dockerfilesChanged: string[];
  sourceFilesChanged: string[];
};

export async function securityDiff(
  root: string,
  base: string,
  head: string
): Promise<SecurityDiffResult> {
  const { stdout } = await execFileAsync(
    'git',
    ['diff', '--name-only', `${base}..${head}`],
    {
      cwd: root,
      encoding: 'utf8'
    }
  );

  const files = stdout.split(/\r?\n/).filter(Boolean);

  return {
    base,
    head,
    files,
    packageManifestChanged: files.some((file) => /(^|\/)package\.json$/.test(file)),
    lockfileChanged: files.some((file) => /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(file)),
    dockerfilesChanged: files.filter((file) => /(^|\/)Dockerfile(?:\..+)?$/.test(file)),
    sourceFilesChanged: files.filter((file) => /\.(js|jsx|ts|tsx|mjs|cjs)$/.test(file))
  };
}
