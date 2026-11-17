import { constants, lstatSync, realpathSync, accessSync } from 'node:fs';
import path from 'node:path';

/**
 * Choose only an explicitly configured absolute Toolip executable, never
 * resolve from PATH and never launch code from a scanned workspace.
 *
 * A user-controlled Git workspace can set .vscode/settings.json. The VS Code
 * client must read *globalValue* for both executable and opt-in settings,
 * never the effective workspace-overridable value.
 */
export function trustedIdeExecutable(
  configured: string | undefined,
  workspaceRoots: readonly string[]
): string | undefined {
  if (
    typeof configured !== 'string' ||
    configured.length === 0 ||
    configured.length > 4096 ||
    configured.includes('\0') ||
    !path.isAbsolute(configured)
  ) return undefined;
  try {
    const leaf = lstatSync(configured);
    // A symlinked executable could be replaced with a project-local payload
    // between validation and spawn. Fail closed rather than following it.
    if (!leaf.isFile() || leaf.isSymbolicLink()) return undefined;
    const executable = realpathSync(configured);
    const metadata = lstatSync(executable);
    if (!metadata.isFile() || metadata.isSymbolicLink()) return undefined;
    if (process.platform !== 'win32')
      accessSync(executable, constants.X_OK);
    // Resolve each workspace root before comparison, so a symlinked project
    // directory cannot evade the containment restriction.
    for (const workspace of workspaceRoots) {
      let root: string;
      try {
        root = realpathSync(workspace);
      } catch {
        return undefined;
      }
      const relative = path.relative(root, executable);
      if (
        relative === '' ||
        (!relative.startsWith('..' + path.sep) &&
          relative !== '..' && !path.isAbsolute(relative))
      ) return undefined;
    }
    return executable;
  } catch {
    return undefined;
  }
}
