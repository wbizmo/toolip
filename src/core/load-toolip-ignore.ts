import path from 'node:path';
import ignore from 'ignore';
import { TextFileReader } from './text-file-reader.js';

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
const maximumIgnoreFileBytes = 1024 * 1024;

export async function loadToolipIgnore(root: string): Promise<ToolipIgnore> {
  const ignoreFile = path.join(root, '.toolipignore');
  let customPatterns: string[] = [];

  const read = await new TextFileReader(
    {
      maxFiles: 1,
      maxFileBytes: maximumIgnoreFileBytes,
      maxTotalBytes: maximumIgnoreFileBytes
    },
    { root }
  ).read(ignoreFile);
  if (read.status === 'ok') {
    const raw = read.content;
    customPatterns = raw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
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
