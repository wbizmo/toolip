import { resolveCommit } from '../git/revision.js';
import { runGitChecked } from '../git/safe-git.js';

export type SecurityDiffResult = {
  base: string;
  head: string;
  baseCommit: string;
  headCommit: string;
  files: string[];
  packageManifestChanged: boolean;
  lockfileChanged: boolean;
  dockerfilesChanged: string[];
  sourceFilesChanged: string[];
};

/**
 * Summarizes the files changed between two commits.
 *
 * Both revisions are validated and resolved to commit OIDs first; only those
 * hexadecimal OIDs reach the diff command, with output-affecting features
 * (external diff, textconv, renames) disabled and a bounded subprocess.
 * Complexity: O(C) for C changed paths in time and space.
 */
export async function securityDiff(
  root: string,
  base: string,
  head: string,
  signal?: AbortSignal
): Promise<SecurityDiffResult> {
  const [baseRev, headRev] = [
    await resolveCommit(root, base, signal),
    await resolveCommit(root, head, signal)
  ];

  const stdout = await runGitChecked(
    [
      'diff',
      '--name-only',
      '-z',
      '--no-ext-diff',
      '--no-textconv',
      '--no-renames',
      baseRev.oid,
      headRev.oid,
      '--'
    ],
    { cwd: root, signal },
    'GIT_DIFF_FAILED'
  );

  const files = stdout.toString('utf8').split('\0').filter(Boolean);

  return {
    base,
    head,
    baseCommit: baseRev.oid,
    headCommit: headRev.oid,
    files,
    packageManifestChanged: files.some((file) =>
      /(^|\/)package\.json$/.test(file)
    ),
    lockfileChanged: files.some((file) =>
      /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(file)
    ),
    dockerfilesChanged: files.filter((file) =>
      /(^|\/)Dockerfile(?:\..+)?$/.test(file)
    ),
    sourceFilesChanged: files.filter((file) =>
      /\.(js|jsx|ts|tsx|mjs|cjs)$/.test(file)
    )
  };
}
