import { createHash } from 'node:crypto';
import { parseDocument } from '../vendor/stage-a-yaml-parser.mjs';

const MAX_POLICY_BYTES = 128 * 1024;
const MAX_ENTRIES = 250;
const MAX_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const ALLOWED_REASONS = new Set([
  'artifact-binary-content-uninspected',
  'dependency-lifecycle-script-review',
  'dynamic-command-resolution',
  'unresolved-child-process-execution',
  'unsupported-toolchain-execution',
  'unverified-npm-resolution'
]);
const validLocation = (value) =>
  typeof value === 'string' &&
  value.length <= 260 &&
  /^node_modules\/(?:[A-Za-z0-9@._-]+\/)*[A-Za-z0-9._-]+$/u.test(value) &&
  !value.split('/').some((part) => part === '.' || part === '..');
const isExactReview = ({ reason, location, sha512 } = {}) =>
  typeof reason === 'string' &&
  reason.length <= 768 &&
  ALLOWED_REASONS.has(reason.split(':', 1)[0]) &&
  validLocation(location) &&
  reason.endsWith(':' + location) &&
  /^[a-f0-9]{128}$/u.test(sha512 ?? '');
const keysWithin = (obj, allowed) =>
  obj &&
  typeof obj === 'object' &&
  !Array.isArray(obj) &&
  Object.keys(obj).every((key) => allowed.includes(key));

/**
 * Parse only an explicit, short-lived risk acceptance in the protected base.
 * The policy is never read from the PR head or from an environment override.
 */
export function parseStageAReviewedDependencyPolicy(text, now = Date.now()) {
  if (text === undefined)
    return Object.freeze({
      entries: Object.freeze([]),
      invalid: false,
      sha256: null
    });
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_POLICY_BYTES)
    return Object.freeze({
      entries: Object.freeze([]),
      invalid: true,
      sha256: null
    });
  let doc;
  try {
    const parsed = parseDocument(text, { prettyErrors: false });
    if (parsed.errors.length) throw new Error('review-policy-ambiguous');
    doc = JSON.parse(text);
  } catch {
    return Object.freeze({
      entries: Object.freeze([]),
      invalid: true,
      sha256: null
    });
  }
  const issued = Date.parse(doc?.issuedAt);
  const expiry = Date.parse(doc?.expiresAt);
  const entries = doc?.entries;
  if (
    !keysWithin(doc, [
      'version',
      'repository',
      'issuedAt',
      'expiresAt',
      'lockfileSha256',
      'entries',
      'reviewedRegistryArchives'
    ]) ||
    doc.version !== 1 ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(doc.repository ?? '') ||
    !/^[a-f0-9]{64}$/u.test(doc.lockfileSha256 ?? '') ||
    !Number.isFinite(issued) ||
    !Number.isFinite(expiry) ||
    new Date(issued).toISOString() !== doc.issuedAt ||
    new Date(expiry).toISOString() !== doc.expiresAt ||
    issued > now ||
    expiry <= now ||
    expiry > issued + MAX_LIFETIME_MS ||
    !Array.isArray(entries) ||
    entries.length > MAX_ENTRIES ||
    entries.some(
      (entry) =>
        !keysWithin(entry, ['reason', 'location', 'sha512']) ||
        !isExactReview(entry)
    ) ||
    new Set(entries.map((entry) => entry.reason)).size !== entries.length ||
    (doc.reviewedRegistryArchives !== undefined &&
      (!keysWithin(
        doc.reviewedRegistryArchives,
        Object.keys(doc.reviewedRegistryArchives ?? {})
      ) ||
        Object.keys(doc.reviewedRegistryArchives).length === 0 ||
        Object.keys(doc.reviewedRegistryArchives).length > 500 ||
        Object.entries(doc.reviewedRegistryArchives).some(
          ([location, digest]) =>
            !validLocation(location) || !/^[a-f0-9]{128}$/u.test(digest ?? '')
        )))
  )
    return Object.freeze({
      entries: Object.freeze([]),
      invalid: true,
      sha256: null
    });
  return Object.freeze({
    entries: Object.freeze(
      entries.map((entry) =>
        Object.freeze({
          reason: entry.reason,
          location: entry.location,
          sha512: entry.sha512
        })
      )
    ),
    repository: doc.repository,
    lockfileSha256: doc.lockfileSha256,
    reviewedRegistryArchives: Object.freeze({
      ...(doc.reviewedRegistryArchives ?? {})
    }),
    sha256: createHash('sha256').update(text, 'utf8').digest('hex'),
    invalid: false
  });
}

/**
 * Applies an explicit reviewed known-dependency baseline only to exact archive
 * uncertainty. Each archive is re-fetched, integrity-verified and inspected
 * on EVERY PR. Failure/structural/provenance codes are never reviewed here.
 *
 * Time O(A + R + E), memory O(A + E), for archive records A, reasons R,
 * approved entries E. No unbounded substring or wildcard comparisons.
 */
export function applyStageAReviewedDependencyPolicy({
  parsed,
  repository,
  currentLockfileSha256,
  baseLockfileSha256,
  changedArtifactCount,
  reasons,
  verifiedArtifactSha512ByLocation,
  verifiedBinaryFilesByLocation
}) {
  const actualReasons = Array.isArray(reasons) ? reasons : [];
  const empty = (extra) =>
    Object.freeze({
      remainingReasons: Object.freeze(
        [...new Set([...actualReasons, ...extra])].sort()
      ),
      reviewedReasons: Object.freeze([]),
      reviewedBinaryFiles: 0,
      baselineSha256: null
    });
  if (parsed?.invalid) return empty(['reviewed-dependency-policy-invalid']);
  if (!parsed || parsed.entries.length === 0) return empty([]);
  if (
    parsed.repository !== repository ||
    parsed.lockfileSha256 !== currentLockfileSha256 ||
    parsed.lockfileSha256 !== baseLockfileSha256 ||
    changedArtifactCount !== 0
  )
    return empty(['reviewed-dependency-lock-or-identity-mismatch']);
  const exactReasons = new Set(actualReasons);
  const approved = new Map(
    parsed.entries.map((entry) => [entry.reason, entry])
  );
  const reviewedReasons = [];
  let reviewedBinaryFiles = 0;
  for (const reason of exactReasons) {
    const entry = approved.get(reason);
    if (
      !entry ||
      verifiedArtifactSha512ByLocation?.[entry.location] !== entry.sha512
    )
      continue;
    const binaryCount = verifiedBinaryFilesByLocation?.[entry.location] ?? 0;
    if (
      !Number.isSafeInteger(binaryCount) ||
      binaryCount < 0 ||
      (reason.startsWith('artifact-binary-content-uninspected:') &&
        binaryCount === 0)
    )
      continue;
    const binaryFiles = reason.startsWith(
      'artifact-binary-content-uninspected:'
    )
      ? binaryCount
      : 0;
    reviewedBinaryFiles += binaryFiles;
    reviewedReasons.push(Object.freeze({ ...entry, binaryFiles }));
  }
  const accepted = new Set(reviewedReasons.map((entry) => entry.reason));
  return Object.freeze({
    remainingReasons: Object.freeze(
      [...exactReasons].filter((reason) => !accepted.has(reason)).sort()
    ),
    reviewedReasons: Object.freeze(
      reviewedReasons.sort((a, b) => a.reason.localeCompare(b.reason))
    ),
    reviewedBinaryFiles,
    baselineSha256: reviewedReasons.length ? parsed.sha256 : null
  });
}

/** Validate coverage/attestations again at the artifact writer and Stage B. */
export function verifyStageAReviewedDependencyEvidence({
  reviewedReasons,
  reviewedBinaryFiles,
  baselineSha256,
  coverage,
  verifiedArtifactSha512ByLocation
}) {
  if (
    !Array.isArray(reviewedReasons) ||
    reviewedReasons.length > MAX_ENTRIES ||
    !Number.isSafeInteger(reviewedBinaryFiles) ||
    reviewedBinaryFiles < 0 ||
    !Number.isSafeInteger(coverage?.dependencyArtifactBinaryFiles) ||
    !Number.isSafeInteger(coverage?.reviewedDependencyBinaryFiles) ||
    reviewedBinaryFiles !== coverage.reviewedDependencyBinaryFiles ||
    reviewedBinaryFiles !== coverage.dependencyArtifactBinaryFiles ||
    !(
      baselineSha256 === null ||
      (typeof baselineSha256 === 'string' &&
        /^[a-f0-9]{64}$/u.test(baselineSha256))
    ) ||
    reviewedReasons.length > 0 !== Boolean(baselineSha256)
  )
    return false;
  const seen = new Set();
  let counted = 0;
  for (const entry of reviewedReasons) {
    if (
      !keysWithin(entry, ['reason', 'location', 'sha512', 'binaryFiles']) ||
      !isExactReview(entry) ||
      seen.has(entry.reason) ||
      !Number.isSafeInteger(entry.binaryFiles) ||
      entry.binaryFiles < 0 ||
      entry.binaryFiles > 10000 ||
      verifiedArtifactSha512ByLocation?.[entry.location] !== entry.sha512 ||
      (entry.reason.startsWith('artifact-binary-content-uninspected:')
        ? entry.binaryFiles < 1
        : entry.binaryFiles !== 0)
    )
      return false;
    seen.add(entry.reason);
    counted += entry.binaryFiles;
  }
  return counted === reviewedBinaryFiles;
}

/**
 * Registry provenance fallback is an explicit owner risk decision for one
 * immutable dependency graph. This is NOT a claim of SLSA provenance.
 * Stage A's scripts-disabled install and npm registry-signature check remain
 * required independently of this policy, and Stage B records the distinction.
 */
export function verifyStageAOperatorReviewedRegistryGraph({
  parsed,
  repository,
  currentLockfileSha256,
  baseLockfileSha256,
  changedArtifactCount,
  verifiedArtifactSha512ByLocation
}) {
  if (
    !parsed ||
    parsed.invalid ||
    parsed.repository !== repository ||
    parsed.lockfileSha256 !== currentLockfileSha256 ||
    parsed.lockfileSha256 !== baseLockfileSha256 ||
    changedArtifactCount !== 0 ||
    !verifiedArtifactSha512ByLocation ||
    typeof verifiedArtifactSha512ByLocation !== 'object' ||
    Array.isArray(verifiedArtifactSha512ByLocation)
  )
    return undefined;
  const approved = parsed.reviewedRegistryArchives;
  if (
    !approved ||
    Object.keys(approved).length === 0 ||
    Object.keys(approved).length !==
      Object.keys(verifiedArtifactSha512ByLocation).length
  )
    return undefined;
  for (const [location, sha512] of Object.entries(approved)) {
    if (
      !validLocation(location) ||
      verifiedArtifactSha512ByLocation[location] !== sha512
    )
      return undefined;
  }
  return Object.freeze({
    status: 'operator-reviewed',
    artifactCount: Object.keys(approved).length,
    provenanceVerifiedCount: 0,
    operatorReviewedCount: Object.keys(approved).length,
    policySha256: parsed.sha256
  });
}
