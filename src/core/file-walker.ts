import path from 'node:path';
import fg from 'fast-glob';
import { loadToolipIgnore } from './load-toolip-ignore.js';

export type ProjectFile = {
  absolutePath: string;
  relativePath: string;
  extension: string;
};

export async function walkProjectFiles(root: string): Promise<ProjectFile[]> {
  const absoluteRoot = path.resolve(root);
  const toolipIgnore = await loadToolipIgnore(absoluteRoot);

  const entries = await fg(['**/*'], {
    cwd: absoluteRoot,
    dot: true,
    onlyFiles: true,
    unique: true,
    followSymbolicLinks: false,
    ignore: toolipIgnore.patterns
  });

  return entries
    .map((entry) => {
      const absolutePath = path.join(absoluteRoot, entry);
      return {
        absolutePath,
        relativePath: entry.replaceAll('\\', '/'),
        extension: path.extname(entry).replace('.', '').toLowerCase()
      };
    })
    .filter((file) => !toolipIgnore.ignores(file.absolutePath))
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}
