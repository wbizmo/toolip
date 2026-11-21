import pacote, { type PackageManifest } from 'pacote';
import { ProviderError, type ScanBudget, withBudget } from './scan-budget.js';

export type NpmPackageManifest = PackageManifest;

/**
 * Fetches a manifest under an optional scan budget. The signal, per-request
 * timeout and zero library retries are passed to pacote (our own bounded retry
 * policy replaces its), and the call also rejects the moment the budget aborts
 * even if the library ignores the signal. A truncated, malformed or
 * name-mismatched response fails closed.
 */
export async function fetchPackageManifest(
  packageName: string,
  budget?: ScanBudget
): Promise<NpmPackageManifest> {
  const registry = 'https://registry.npmjs.org';
  if (!budget) {
    return validate(
      packageName,
      await pacote.manifest(packageName, { registry })
    );
  }

  const manifest = await withBudget(
    (signal) =>
      pacote.manifest(packageName, {
        registry,
        signal,
        timeout: budget.requestTimeoutMs,
        fetchRetries: 0
      }),
    budget
  );
  return validate(packageName, manifest);
}

function validate(requested: string, manifest: unknown): NpmPackageManifest {
  const candidate = manifest as Partial<NpmPackageManifest> | null | undefined;
  if (
    !candidate ||
    typeof candidate !== 'object' ||
    typeof candidate.name !== 'string' ||
    typeof candidate.version !== 'string'
  ) {
    throw new ProviderError(
      'failed',
      `Registry returned a malformed manifest for ${requested}; refusing to treat it as healthy.`
    );
  }
  return candidate as NpmPackageManifest;
}
