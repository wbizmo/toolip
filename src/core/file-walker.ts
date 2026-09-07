import path from 'node:path';
import fg from 'fast-glob';
import { ToolipError } from '../errors/toolip-error.js';
import { loadToolipIgnore } from './load-toolip-ignore.js';

export type ProjectFile = {
  absolutePath: string;
  relativePath: string;
  extension: string;
};

export type FileWalkOptions = {
  maxFiles?: number;
};

const defaultMaxFiles = 50_000;

export async function walkProjectFiles(
  root: string,
  options: FileWalkOptions = {}
): Promise<ProjectFile[]> {
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

  const maxFiles = options.maxFiles ?? defaultMaxFiles;
  if (entries.length > maxFiles) {
    throw new ToolipError(
      `Project discovery found ${entries.length} files, above the configured limit of ${maxFiles}. Refine .toolipignore or raise the scan budget explicitly.`,
      { code: 'SCAN_FILE_LIMIT_EXCEEDED' }
    );
  }

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
