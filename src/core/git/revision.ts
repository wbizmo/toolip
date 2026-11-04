import { ToolipError } from '../../errors/toolip-error.js';
import { runGit } from './safe-git.js';

/**
 * Accepts only plain ref names and (abbreviated) object IDs: a leading
 * alphanumeric/underscore, then letters, digits and `._/@+-`. Everything that
 * Git would interpret as an option, revision expression or range is rejected
 * (`-x`, `--output=f`, `a..b`, `a...b`, `HEAD~1`, `HEAD^`, `x:path`, `@{u}`,
 * whitespace, control characters, NUL). O(length).
 */
const SAFE_REVISION = /^[A-Za-z0-9_][A-Za-z0-9._/@+-]{0,199}$/u;

export function isSafeRevisionSyntax(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    SAFE_REVISION.test(value) &&
    !value.includes('..') &&
    !value.includes('@{') &&
    !value.includes('//') &&
    !value.endsWith('/') &&
    !value.endsWith('.') &&
    !value.endsWith('.lock')
  );
}

export type ResolvedRevision = {
  /** The caller-supplied name, for display only. */
  input: string;
  /** Immutable commit object ID. */
  oid: string;
};

/**
 * Resolves a revision to an immutable commit OID with explicit, reviewed Git
 * arguments. Syntax is validated first, `--end-of-options` stops Git from
 * parsing the operand as an option even if validation were ever loosened, and
 * only the resulting hexadecimal OID is used to compose later commands.
 */
export async function resolveCommit(
  root: string,
  revision: string,
  signal?: AbortSignal
): Promise<ResolvedRevision> {
  if (!isSafeRevisionSyntax(revision)) {
    throw new ToolipError(
      'Invalid Git revision. Use a branch, tag, HEAD or commit ID; ranges, options and revision expressions such as HEAD~1 are not accepted.',
      { code: 'GIT_REVISION_INVALID', exitCode: 1 }
    );
  }

  const result = await runGit(
    [
      'rev-parse',
      '--verify',
      '--quiet',
      '--end-of-options',
      `${revision}^{commit}`
    ],
    { cwd: root, timeoutMs: 10_000, maxBuffer: 1024, signal }
  );

  const oid = result.stdout.toString('utf8').trim();
  if (result.code !== 0 || !/^[0-9a-f]{40,64}$/u.test(oid)) {
    throw new ToolipError('Git revision was not found in this repository.', {
      code: 'GIT_REVISION_NOT_FOUND',
      exitCode: 1
    });
  }

  return { input: revision, oid };
}
