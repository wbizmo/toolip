import { createHash } from 'node:crypto';

export type StageAStatus = 'approved' | 'blocked' | 'incomplete' | 'error';
export type StageAResult = Readonly<{
  status: StageAStatus;
  scannerSha256: string;
  inputSha256: string;
  reasons: readonly string[];
}>;
export type StageATrustPolicy = Readonly<{
  scannerSha256Allowlist: readonly string[];
}>;

/** Non-exportable construction token: project code cannot mint approval. */
const authorized = new WeakSet<object>();
export type StageAApproval = Readonly<{
  readonly stageAApproval: unique symbol;
}>;

/** Hashes sorted immutable Git-blob tuples; O(B+F), with O(F) metadata space. */
export function hashStageAInput(
  blobs: readonly { path: string; oid: string; content: Uint8Array }[]
): string {
  const ordered = [...blobs].sort((a, b) => a.path.localeCompare(b.path));
  const hash = createHash('sha256');
  for (const blob of ordered) {
    hash.update(blob.path).update('\0').update(blob.oid).update('\0');
    hash
      .update(createHash('sha256').update(blob.content).digest('hex'))
      .update('\n');
  }
  return hash.digest('hex');
}

/**
 * Fails closed if the independently pinned scanner, exact input inventory,
 * bounded run, or analysis result is missing/unknown. Signatures establish
 * provenance only; they do not assert that the repository is benign.
 */
export function evaluateStageA(input: {
  policy: StageATrustPolicy;
  scannerBytes?: Uint8Array;
  blobs?: readonly { path: string; oid: string; content: Uint8Array }[];
  scannerAvailable: boolean;
  completed: boolean;
  findingsKnown: boolean;
  blocked: boolean;
}): { result: StageAResult; approval?: StageAApproval } {
  const scannerSha256 = input.scannerBytes
    ? createHash('sha256').update(input.scannerBytes).digest('hex')
    : '';
  const inputSha256 = input.blobs ? hashStageAInput(input.blobs) : '';
  let status: StageAStatus = 'incomplete';
  let reasons: string[] = [];
  if (
    !input.scannerAvailable ||
    !input.scannerBytes ||
    !input.policy.scannerSha256Allowlist.includes(scannerSha256)
  ) {
    status = 'blocked';
    reasons = ['trusted scanner unavailable or digest is not approved'];
  } else if (!input.blobs || !input.completed || !input.findingsKnown) {
    status = 'incomplete';
    reasons = [
      'exact input inventory or complete Stage A result is unavailable'
    ];
  } else if (input.blocked) {
    status = 'blocked';
    reasons = ['Stage A detected a policy-blocking condition'];
  } else {
    status = 'approved';
    reasons = [];
  }
  const result = Object.freeze({
    status,
    scannerSha256,
    inputSha256,
    reasons: Object.freeze(reasons)
  });
  if (status !== 'approved') return { result };
  const token = Object.freeze({}) as StageAApproval;
  authorized.add(token as object);
  return { result, approval: token };
}

/** The only supported transition into Stage B; blocked runs never invoke it. */
export async function runStageB<T>(
  approval: StageAApproval,
  action: () => Promise<T>
): Promise<T> {
  if (!authorized.has(approval as object))
    throw new Error('valid Stage A approval is required before Stage B');
  authorized.delete(approval as object);
  return action();
}
