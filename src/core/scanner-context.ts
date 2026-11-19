import path from 'node:path';
import { walkProjectFiles, type ProjectFile } from './file-walker.js';
import { profileProject, type ProjectProfile } from './profile-project.js';

export type ScannerContext = {
  root: string;
  profile: ProjectProfile;
  files: ProjectFile[];
  summary: {
    totalFiles: number;
    extensions: Record<string, number>;
  };
};

export type ProjectContext = ScannerContext;

/** Freeze every mutable object shared by analyzers in one scan. */
export function freezeScannerContext(context: ScannerContext): ScannerContext {
  const profile = Object.freeze({
    ...context.profile,
    detected: Object.freeze([...context.profile.detected]),
    languages: Object.freeze({ ...context.profile.languages }),
    packageScripts: Object.freeze([...context.profile.packageScripts])
  }) as ProjectProfile;
  const files = context.files.map((file) => {
    if (file.snapshot) Object.freeze(file.snapshot);
    return Object.freeze(file);
  });
  const summary = Object.freeze({
    totalFiles: context.summary.totalFiles,
    extensions: Object.freeze({ ...context.summary.extensions })
  });
  return Object.freeze({
    root: context.root,
    profile,
    files: Object.freeze(files) as ProjectFile[],
    summary
  });
}

function summarizeExtensions(
  files: readonly ProjectFile[]
): Record<string, number> {
  return files.reduce<Record<string, number>>((summary, file) => {
    const key = file.extension || 'none';
    summary[key] = (summary[key] ?? 0) + 1;
    return summary;
  }, {});
}

export async function createScannerContext(
  root: string,
  options: { maxFiles?: number; signal?: AbortSignal } = {}
): Promise<ScannerContext> {
  const absoluteRoot = path.resolve(root);
  const files = await walkProjectFiles(absoluteRoot, {
    maxFiles: options.maxFiles,
    signal: options.signal,
    includeTrackedIgnored: true
  });
  const profile = await profileProject(absoluteRoot, files);

  return freezeScannerContext({
    root: absoluteRoot,
    profile,
    files,
    summary: {
      totalFiles: files.length,
      extensions: summarizeExtensions(files)
    }
  });
}

export const createProjectContext = createScannerContext;
