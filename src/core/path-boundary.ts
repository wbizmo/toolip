import path from 'node:path';

/** Returns a stable path identity for platform-safe containment checks. */
export function comparablePath(
  value: string,
  platform: NodeJS.Platform = process.platform
): string {
  const pathApi = platform === 'win32' ? path.win32 : path;
  let resolved = pathApi.resolve(value);
  if (platform === 'win32') {
    if (/^\\\\\?\\UNC\\/iu.test(resolved))
      resolved = `\\\\${resolved.slice(8)}`;
    else if (/^\\\\\?\\/u.test(resolved)) resolved = resolved.slice(4);
    return resolved.toLowerCase();
  }
  return resolved;
}

/** Checks canonical path containment without string-prefix assumptions. */
export function isWithinPath(
  root: string,
  candidate: string,
  platform: NodeJS.Platform = process.platform
): boolean {
  const pathApi = platform === 'win32' ? path.win32 : path;
  const relative = pathApi.relative(
    comparablePath(root, platform),
    comparablePath(candidate, platform)
  );
  return (
    relative === '' ||
    (!pathApi.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${pathApi.sep}`))
  );
}
