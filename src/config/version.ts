import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

type PackageManifest = {
  name?: string;
  version?: string;
};

function resolvePackageVersion(): string {
  let directory = path.dirname(fileURLToPath(import.meta.url));
  const root = path.parse(directory).root;

  while (directory !== root) {
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

    directory = path.dirname(directory);
  }

  throw new Error(
    'Unable to resolve Toolip version from package.json.'
  );
}

export const TOOLIP_VERSION = resolvePackageVersion();

export const TOOLIP_AUTHOR = {
  name: 'Ashibuogwu Williams',
  handle: 'wbizmo',
  github: 'https://github.com/wbizmo'
};
