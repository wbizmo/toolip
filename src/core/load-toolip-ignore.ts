import { readFile } from 'node:fs/promises';
import path from 'node:path';
import ignore from 'ignore';

export type ToolipIgnore = {
  ignores(filePath: string, isDirectory?: boolean): boolean;
  patterns: string[];
};

const defaultPatterns = [
  'node_modules',
  'dist',
  'coverage',
  'build',
  '.git',
  '.toolip-vault.json'
];

export async function loadToolipIgnore(root: string): Promise<ToolipIgnore> {
  const ignoreFile = path.join(root, '.toolipignore');
  let customPatterns: string[] = [];

  try {
    const raw = await readFile(ignoreFile, 'utf8');
    customPatterns = raw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
  } catch {
    customPatterns = [];
  }

  const patterns = [...defaultPatterns, ...customPatterns];
  const ig = ignore().add(patterns);

  return {
    patterns,
    ignores(filePath: string, isDirectory = false): boolean {
      const relativePath = path.relative(root, filePath).replaceAll('\\', '/');
      if (relativePath.length === 0) return false;
      // The ignore package uses a trailing slash to distinguish a directory
      // match. Keep that detail here because path.relative() removes it.
      return ig.ignores(isDirectory ? `${relativePath}/` : relativePath);
    }
  };
}
