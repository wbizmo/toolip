import { createHash } from 'node:crypto';
import type { Finding } from '../contracts/finding.js';
import type { ProjectFile } from './file-walker.js';
import type { FileSnapshot, TextFileReadResult } from './text-file-reader.js';

type SuccessfulRead = Extract<TextFileReadResult, { status: 'ok' }>;

/** JSON-safe identity metadata for a discovered or descriptor-verified read. */
export type SourceProvenance = {
  path: string;
  sha256: string;
  bytes: number;
  discoverySnapshot?: SerializedFileSnapshot;
  readSnapshot?: SerializedFileSnapshot;
};

type SerializedFileSnapshot = {
  dev: string;
  ino: string;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
};

/** Binds source findings to the exact content digest and checked file identity. */
export function bindSourceProvenance(
  findings: Finding[],
  file: ProjectFile,
  read: SuccessfulRead
): Finding[] {
  if (findings.length === 0) return findings;

  const provenance = sourceProvenanceFor(file, read);

  return findings.map((finding) => ({
    ...finding,
    metadata: {
      ...finding.metadata,
      sourceProvenance: provenance
    }
  }));
}

/** Builds JSON-safe provenance for one successfully analyzed source file. */
export function sourceProvenanceFor(
  file: ProjectFile,
  read: SuccessfulRead
): SourceProvenance {
  return {
    path: file.relativePath,
    sha256:
      read.sha256 ?? createHash('sha256').update(read.content).digest('hex'),
    bytes: read.bytes,
    ...(file.snapshot
      ? { discoverySnapshot: serializeSnapshot(file.snapshot) }
      : {}),
    ...(read.snapshot ? { readSnapshot: serializeSnapshot(read.snapshot) } : {})
  };
}

/** Serializes bigint filesystem identity without breaking JSON reports. */
export function serializeSnapshot(
  snapshot: FileSnapshot
): SerializedFileSnapshot {
  return {
    dev: snapshot.dev.toString(),
    ino: snapshot.ino.toString(),
    size: snapshot.size,
    mtimeMs: snapshot.mtimeMs,
    ctimeMs: snapshot.ctimeMs
  };
}
