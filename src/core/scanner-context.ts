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

function summarizeExtensions(files: ProjectFile[]): Record<string, number> {
  return files.reduce<Record<string, number>>((summary, file) => {
    const key = file.extension || 'none';
    summary[key] = (summary[key] ?? 0) + 1;
    return summary;
  }, {});
}

export async function createScannerContext(root: string): Promise<ScannerContext> {
  const absoluteRoot = path.resolve(root);
  const [profile, files] = await Promise.all([
    profileProject(absoluteRoot),
    walkProjectFiles(absoluteRoot)
  ]);

  return {
    root: absoluteRoot,
    profile,
    files,
    summary: {
      totalFiles: files.length,
      extensions: summarizeExtensions(files)
    }
  };
}
