import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

type PackageManifest = {
  name?: string;
  version?: string;
};

function resolvePackageVersion(): string {
  let directory = path.dirname(fileURLToPath(import.meta.url));
  const filesystemRoot = path.parse(directory).root;

  while (true) {
    const manifestPath = path.join(directory, 'package.json');

    try {
      const manifest = JSON.parse(
        readFileSync(manifestPath, 'utf8')
      ) as PackageManifest;

      if (
        manifest.name === 'toolip' &&
        typeof manifest.version === 'string'
      ) {
        return manifest.version;
      }
    } catch {
      // Continue searching parent directories.
    }

    if (directory === filesystemRoot) {
      break;
    }

    directory = path.dirname(directory);
  }

  return '0.0.0';
}

export const TOOLIP_VERSION = resolvePackageVersion();

export const TOOLIP_AUTHOR = {
  name: 'Ashibuogwu Williams',
  handle: 'wbizmo',
  github: 'https://github.com/wbizmo'
};
