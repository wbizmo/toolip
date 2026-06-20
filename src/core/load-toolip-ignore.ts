import { readFile } from 'node:fs/promises';
import path from 'node:path';
import ignore from 'ignore';

export type ToolipIgnore = {
  ignores(filePath: string): boolean;
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
    ignores(filePath: string): boolean {
      const relativePath = path.relative(root, filePath).replaceAll('\\', '/');
      return relativePath.length > 0 && ig.ignores(relativePath);
    }
  };
}
