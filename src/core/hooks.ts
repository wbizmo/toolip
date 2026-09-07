import {
  chmod,
  mkdir,
  readFile,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import { ToolipError } from '../errors/toolip-error.js';

const managedStart = '# >>> toolip managed pre-commit >>>';
const managedEnd = '# <<< toolip managed pre-commit <<<';

const managedBlock = `${managedStart}
echo "Running Toolip pre-commit checks..."
if [ ! -x "./node_modules/.bin/toolip" ]; then
  echo "Toolip pre-commit hook requires a project-local Toolip installation." >&2
  exit 1
fi
./node_modules/.bin/toolip pre-commit --path .
status=$?
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
${managedEnd}`;

export async function installPreCommitHook(root: string): Promise<string> {
  const hooksDir = path.join(root, '.git', 'hooks');
  const hookPath = path.join(hooksDir, 'pre-commit');

  await mkdir(hooksDir, { recursive: true });

  let existing = '';
  try {
    existing = await readFile(hookPath, 'utf8');
  } catch (error) {
    if (errorCode(error) !== 'ENOENT') throw error;
  }

  const content = mergeManagedBlock(existing);
  await writeFile(hookPath, content, 'utf8');
  await chmod(hookPath, 0o755);

  return hookPath;
}

function mergeManagedBlock(existing: string): string {
  const start = existing.indexOf(managedStart);
  const end = existing.indexOf(managedEnd);

  if ((start === -1) !== (end === -1) || (start !== -1 && end < start)) {
    throw new ToolipError(
      'Existing pre-commit hook contains an incomplete Toolip-managed block. Repair it manually before reinstalling.',
      {
        code: 'HOOK_MANAGED_BLOCK_CORRUPT',
        exitCode: 1
      }
    );
  }

  if (start !== -1) {
    const after = end + managedEnd.length;
    return `${existing.slice(0, start)}${managedBlock}${existing.slice(after)}`
      .replace(/\s*$/, '\n');
  }

  if (existing.length === 0) {
    return `#!/bin/sh\n${managedBlock}\n`;
  }

  const prefix = existing.endsWith('\n') ? existing : `${existing}\n`;
  return `${prefix}\n${managedBlock}\n`;
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
