import { mkdir, writeFile, chmod } from 'node:fs/promises';
import path from 'node:path';

export async function installPreCommitHook(root: string): Promise<string> {
  const hooksDir = path.join(root, '.git', 'hooks');
  const hookPath = path.join(hooksDir, 'pre-commit');

  await mkdir(hooksDir, { recursive: true });

  await writeFile(
    hookPath,
    `#!/bin/sh
echo "Running Toolip pre-commit checks..."
npx toolip pre-commit
`,
    'utf8'
  );

  await chmod(hookPath, 0o755);

  return hookPath;
}
