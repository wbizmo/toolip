import path from 'node:path';
import { lstat, realpath, stat as statTarget } from 'node:fs/promises';
import fg from 'fast-glob';
import { mapConcurrent } from '../application/concurrency.js';
import { ToolipError } from '../errors/toolip-error.js';
import { loadToolipIgnore } from './load-toolip-ignore.js';
import { snapshotOf, type FileSnapshot } from './text-file-reader.js';

export type ProjectFile = {
  absolutePath: string;
  relativePath: string;
  extension: string;
  snapshot?: FileSnapshot;
};

export type FileWalkOptions = {
  maxFiles?: number;
  statTarget?: typeof statTarget;
};

const metadataConcurrency = 32;
const defaultMaxFiles = 50_000;

/** Discovers eligible project files with bounded, snapshot-aware metadata reads. */
export async function walkProjectFiles(
  root: string,
  options: FileWalkOptions = {}
): Promise<ProjectFile[]> {
  const absoluteRoot = await realpath(path.resolve(root));
  const toolipIgnore = await loadToolipIgnore(absoluteRoot);
  const resolveTargetStat = options.statTarget ?? statTarget;

  const entries = await fg(['**/*'], {
    cwd: absoluteRoot,
    dot: true,
    onlyFiles: false,
    unique: true,
    followSymbolicLinks: false,
    ignore: toolipIgnore.patterns
  });

  const maxFiles = options.maxFiles ?? defaultMaxFiles;
  const files = await mapConcurrent(
    entries,
    metadataConcurrency,
    async (entry) => {
      const absolutePath = path.join(absoluteRoot, entry);
      try {
        // Skip ordinary file-pattern matches before metadata I/O. Directory-
        // only rules are checked again after a symlink target is classified.
        if (toolipIgnore.ignores(absolutePath)) return undefined;
        const stat = await lstat(absolutePath, { bigint: true });
        let isDirectory = stat.isDirectory();
        if (stat.isSymbolicLink()) {
          try {
            isDirectory = (await resolveTargetStat(absolutePath)).isDirectory();
            if (isDirectory) {
              if (toolipIgnore.ignores(absolutePath, true)) return undefined;
              throw new ToolipError(
                `Project discovery encountered a symbolic directory at ${entry}; traversal is incomplete.`,
                { code: 'SCAN_DISCOVERY_INCOMPLETE' }
              );
            }
          } catch (error) {
            if (error instanceof ToolipError) throw error;
            if (
              error === null ||
              typeof error !== 'object' ||
              !('code' in error) ||
              error.code !== 'ENOENT'
            ) {
              throw error;
            }
            // A dangling or concurrently changed symbolic link is kept as a
            // file entry so its later descriptor read is reported incomplete.
          }
        }
        if (toolipIgnore.ignores(absolutePath, isDirectory)) return undefined;
        if (isDirectory) return undefined;
        if (!stat.isFile() && !stat.isSymbolicLink()) return undefined;
        return {
          absolutePath,
          relativePath: entry.replaceAll('\\', '/'),
          extension: path.extname(entry).replace('.', '').toLowerCase(),
          snapshot: snapshotOf(stat)
        } satisfies ProjectFile;
      } catch (error) {
        throw new ToolipError(
          `Project discovery could not inspect ${entry}: ${error instanceof Error ? error.message : String(error)}`,
          { code: 'SCAN_DISCOVERY_INCOMPLETE' }
        );
      }
    }
  );

  const discovered = files
    .flatMap((file) => (file === undefined ? [] : [file]))
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  if (discovered.length > maxFiles) {
    throw new ToolipError(
      `Project discovery found ${discovered.length} files, above the configured limit of ${maxFiles}. Refine .toolipignore or raise the scan budget explicitly.`,
      { code: 'SCAN_FILE_LIMIT_EXCEEDED' }
    );
  }
  return discovered;
}
