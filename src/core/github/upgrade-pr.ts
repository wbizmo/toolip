import { readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';

const execFileAsync = promisify(execFile);

export async function createUpgradePullRequest(
  root: string,
  packageName: string,
  targetVersion: string,
  dryRun: boolean
): Promise<{ branch: string; changed: boolean }> {
  const manifestPath = path.join(root, 'package.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as Record<string, any>;
  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  let changed = false;

  for (const section of sections) {
    if (manifest[section]?.[packageName]) {
      manifest[section][packageName] = targetVersion;
      changed = true;
    }
  }

  if (!changed) {
    throw new Error(`${packageName} is not declared in package.json.`);
  }

  const branch = `toolip/upgrade-${packageName.replaceAll(/[^A-Za-z0-9]/g, '-')}-${targetVersion}`;

  if (dryRun) {
    return { branch, changed: true };
  }

  await execFileAsync('git', ['switch', '-c', branch], { cwd: root });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  await execFileAsync('npm', ['install', '--package-lock-only'], { cwd: root });
  await execFileAsync('npm', ['test'], { cwd: root });
  await execFileAsync('git', ['add', 'package.json', 'package-lock.json'], { cwd: root });
  await execFileAsync('git', ['commit', '-m', `chore: upgrade ${packageName} to ${targetVersion}`], { cwd: root });
  await execFileAsync('git', ['push', '-u', 'origin', branch], { cwd: root });
  await execFileAsync(
    'gh',
    [
      'pr',
      'create',
      '--title',
      `chore: upgrade ${packageName} to ${targetVersion}`,
      '--body',
      `Toolip generated this dependency upgrade after updating the lockfile and running the project test suite.`
    ],
    { cwd: root }
  );

  return { branch, changed: true };
}
