import pacote, { type PackageManifest } from 'pacote';

export type NpmPackageManifest = PackageManifest;

export async function fetchPackageManifest(packageName: string): Promise<NpmPackageManifest> {
  return pacote.manifest(packageName);
}
