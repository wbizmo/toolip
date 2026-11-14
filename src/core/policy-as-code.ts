import { createHash, verify as cryptoVerify } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import { canonicalJson } from './canonical-json.js';
import { readPemKeyFile } from './secure-key-file.js';
import type { AnalysisState } from '../contracts/analysis.js';
import type { Finding, FindingSeverity } from '../contracts/finding.js';

const severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const ruleSets = [
  'all',
  'application-security',
  'infrastructure',
  'secrets',
  'supply-chain',
  'git-security'
] as const;
const maximumPolicyRules = 5_000;
const maximumPolicySuppressions = 1_000;

function isSafeSuppressionPattern(pattern: string): boolean {
  return (
    !pattern.startsWith('/') &&
    !pattern.includes('..') &&
    !pattern.includes('\\') &&
    !pattern.includes('\0')
  );
}

const policySchema = z
  .object({
    version: z.literal(1),
    minimumSeverity: severity.optional(),
    minimumCoverage: z.number().min(0).max(1).optional(),
    blockKnownExploited: z.boolean().optional(),
    ruleSets: z.array(z.enum(ruleSets)).min(1).max(ruleSets.length).optional(),
    rules: z
      .record(
        z.string().min(1),
        z
          .object({
            enabled: z.boolean().optional(),
            severity: severity.optional()
          })
          .strict()
      )
      .default({}),
    suppressions: z
      .array(
        z
          .object({
            id: z.string().min(1).max(100),
            ruleId: z.string().min(1).max(128),
            path: z
              .string()
              .min(1)
              .max(512)
              .refine(isSafeSuppressionPattern)
              .optional(),
            expiresAt: z.string().datetime(),
            reason: z.string().min(1).max(500)
          })
          .strict()
      )
      .default([])
  })
  .strict()
  .superRefine((value, context) => {
    const ids = new Set<string>();
    for (const [index, suppression] of value.suppressions.entries()) {
      if (ids.has(suppression.id)) {
        context.addIssue({
          code: 'custom',
          path: ['suppressions', index, 'id'],
          message: 'suppression IDs must be unique'
        });
      }
      ids.add(suppression.id);
    }
    if (
      value.ruleSets &&
      new Set(value.ruleSets).size !== value.ruleSets.length
    ) {
      context.addIssue({
        code: 'custom',
        path: ['ruleSets'],
        message: 'rule sets must be unique'
      });
    }
    if (Object.keys(value.rules).length > maximumPolicyRules) {
      context.addIssue({
        code: 'custom',
        path: ['rules'],
        message: 'policy contains too many per-rule overrides'
      });
    }
    if (value.suppressions.length > maximumPolicySuppressions) {
      context.addIssue({
        code: 'custom',
        path: ['suppressions'],
        message: 'policy contains too many suppressions'
      });
    }
  });

export type PolicyAsCode = z.infer<typeof policySchema>;
export type PolicyTrust = {
  trusted: boolean;
  source: 'repository' | 'user-config' | 'signed';
  /** Stable signer and envelope identity; required for privileged policy. */
  identity?: string;
};
export type PolicyDecision =
  'pass' | 'fail' | 'incomplete' | 'misconfigured' | 'error';

const ruleSetCategories: Record<(typeof ruleSets)[number], readonly string[]> =
  {
    all: ['*'],
    'application-security': [
      'configuration',
      'dangerous-code',
      'authorization',
      'concurrency',
      'sensitive-data',
      'malicious-content',
      'security-headers'
    ],
    infrastructure: ['container', 'infrastructure'],
    secrets: ['secrets', 'git-history-secret'],
    'supply-chain': [
      'dependency-confusion',
      'install-script',
      'license',
      'reachability',
      'supply-chain',
      'vulnerability'
    ],
    'git-security': ['git-security', 'git-history-secret']
  };

export type PolicyLayer = Readonly<{
  policy: PolicyAsCode;
  trust: PolicyTrust;
}>;

/** Organization rules override repository policy; only trusted organization
 * suppressions can become privileged in the resulting policy layer. */
export function mergePolicyLayers(
  repository: PolicyAsCode,
  organization?: PolicyLayer
): PolicyLayer {
  const repositoryRules = Object.fromEntries(
    Object.entries(repository.rules).map(([ruleId, rule]) => [
      ruleId,
      { ...rule, enabled: rule.enabled === false ? undefined : rule.enabled }
    ])
  );
  if (!organization) {
    return {
      policy: { ...repository, rules: repositoryRules },
      trust: { trusted: false, source: 'repository' }
    };
  }
  const trusted =
    organization.trust.trusted === true &&
    organization.trust.source === 'signed' &&
    typeof organization.trust.identity === 'string' &&
    organization.trust.identity.length > 0;
  const severityOrder: Record<z.infer<typeof severity>, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  };
  const organizationRules = trusted
    ? organization.policy.rules
    : Object.fromEntries(
        Object.entries(organization.policy.rules).map(([ruleId, rule]) => [
          ruleId,
          {
            ...rule,
            enabled: rule.enabled === false ? undefined : rule.enabled
          }
        ])
      );
  return {
    policy: {
      version: 1,
      minimumSeverity: trusted
        ? (organization.policy.minimumSeverity ?? repository.minimumSeverity)
        : [repository.minimumSeverity, organization.policy.minimumSeverity]
            .filter(
              (value): value is z.infer<typeof severity> => value !== undefined
            )
            .sort(
              (left, right) => severityOrder[left] - severityOrder[right]
            )[0],
      minimumCoverage: trusted
        ? (organization.policy.minimumCoverage ?? repository.minimumCoverage)
        : Math.max(
            repository.minimumCoverage ?? 0,
            organization.policy.minimumCoverage ?? 0
          ) || undefined,
      blockKnownExploited: trusted
        ? (organization.policy.blockKnownExploited ??
          repository.blockKnownExploited)
        : repository.blockKnownExploited === true ||
          organization.policy.blockKnownExploited === true,
      ruleSets: trusted
        ? (organization.policy.ruleSets ?? repository.ruleSets)
        : repository.ruleSets,
      rules: { ...repositoryRules, ...organizationRules },
      suppressions: trusted ? organization.policy.suppressions : []
    },
    trust: trusted
      ? organization.trust
      : { trusted: false, source: 'repository' }
  };
}

export type PolicyEvaluation = Readonly<{
  decision: PolicyDecision;
  findings: readonly Finding[];
  suppressed: readonly string[];
  policySha256: string;
  reasons: readonly string[];
}>;

/** Strict JSON/YAML parser: duplicate mapping keys and unknown fields fail closed. */
export async function loadPolicyAsCode(
  filePath: string
): Promise<{ policy: PolicyAsCode; sha256: string }> {
  return parsePolicyAsCode(await readBoundedPolicySource(filePath));
}

async function readBoundedPolicySource(filePath: string): Promise<string> {
  const maximumBytes = 1_048_576;
  const before = await lstat(filePath, { bigint: true });
  if (!before.isFile() || before.size > BigInt(maximumBytes))
    throw new Error('policy file is not a bounded regular file');
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(filePath, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    )
      throw new Error('policy file changed while opening');
    const bytes = Buffer.alloc(maximumBytes + 1);
    let byteLength = 0;
    while (byteLength < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        byteLength,
        Math.min(64 * 1024, bytes.length - byteLength),
        null
      );
      if (bytesRead === 0) break;
      byteLength += bytesRead;
    }
    if (byteLength > maximumBytes)
      throw new Error('policy file exceeds the size budget');
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(filePath, { bigint: true });
    if (
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size !== after.size ||
      opened.mtimeNs !== after.mtimeNs ||
      opened.ctimeNs !== after.ctimeNs ||
      afterPath.isSymbolicLink() ||
      afterPath.dev !== opened.dev ||
      afterPath.ino !== opened.ino
    )
      throw new Error('policy file changed while reading');
    if (BigInt(byteLength) !== opened.size)
      throw new Error('policy file changed while reading');
    return new TextDecoder('utf-8', { fatal: true }).decode(
      bytes.subarray(0, byteLength)
    );
  } finally {
    await handle.close();
  }
}

/**
 * Loads an organization profile only when its canonical envelope verifies
 * against an independently configured Ed25519 key ID and issuer. The caller
 * must source these trust settings outside the scanned repository.
 */
export async function loadTrustedOrganizationPolicy(input: {
  filePath: string;
  publicKeyPath: string;
  trustedKeyId: string;
  trustedIssuer: string;
  now?: number;
}): Promise<{
  policy: PolicyAsCode;
  sha256: string;
  identity: string;
  issuer: string;
  keyId: string;
}> {
  const source = await readBoundedPolicySource(input.filePath);
  const document = parseDocument(source, {
    uniqueKeys: true,
    prettyErrors: false
  });
  if (document.errors.length)
    throw new Error(
      'organization policy envelope is malformed or has duplicate keys'
    );
  const parsed = document.toJS() as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    throw new Error('organization policy envelope is invalid');
  const envelope = parsed as Record<string, unknown>;
  const signature = envelope.signature;
  const validKeySet = (value: Record<string, unknown>, keys: string[]) =>
    Object.keys(value).length === keys.length &&
    Object.keys(value).every((key) => keys.includes(key));
  if (
    !validKeySet(envelope, [
      'schema',
      'issuer',
      'keyId',
      'issuedAt',
      'expiresAt',
      'policy',
      'signature'
    ]) ||
    envelope.schema !== 'toolip.dev/organization-policy/v1' ||
    typeof envelope.issuer !== 'string' ||
    typeof envelope.keyId !== 'string' ||
    typeof envelope.issuedAt !== 'string' ||
    typeof envelope.expiresAt !== 'string' ||
    !envelope.policy ||
    typeof envelope.policy !== 'object' ||
    Array.isArray(envelope.policy) ||
    !signature ||
    typeof signature !== 'object' ||
    Array.isArray(signature)
  )
    throw new Error('organization policy envelope is invalid or unsupported');
  const signatureRecord = signature as Record<string, unknown>;
  if (
    !validKeySet(signatureRecord, ['algorithm', 'value']) ||
    signatureRecord.algorithm !== 'Ed25519' ||
    typeof signatureRecord.value !== 'string' ||
    !/^[A-Za-z0-9+/]{86}==$/u.test(signatureRecord.value)
  )
    throw new Error('organization policy signature envelope is invalid');
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(input.trustedKeyId) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u.test(input.trustedIssuer) ||
    envelope.keyId !== input.trustedKeyId ||
    envelope.issuer !== input.trustedIssuer
  )
    throw new Error('organization policy signer or issuer is not trusted');
  const issuedAt = Date.parse(envelope.issuedAt);
  const expiresAt = Date.parse(envelope.expiresAt);
  const now = input.now ?? Date.now();
  const maxLifetime = 180 * 24 * 60 * 60 * 1000;
  if (
    !Number.isFinite(issuedAt) ||
    !Number.isFinite(expiresAt) ||
    new Date(issuedAt).toISOString() !== envelope.issuedAt ||
    new Date(expiresAt).toISOString() !== envelope.expiresAt ||
    issuedAt > now + 5 * 60 * 1000 ||
    expiresAt <= now ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > maxLifetime
  )
    throw new Error(
      'organization policy is expired or has invalid validity dates'
    );
  const { signature: _signature, ...payload } = envelope;
  let validSignature = false;
  try {
    const signatureBytes = Buffer.from(signatureRecord.value, 'base64');
    if (
      signatureBytes.length !== 64 ||
      signatureBytes.toString('base64') !== signatureRecord.value
    )
      throw new Error('invalid Ed25519 signature encoding');
    validSignature = cryptoVerify(
      null,
      Buffer.from(canonicalJson(payload)),
      await readPemKeyFile(input.publicKeyPath),
      signatureBytes
    );
  } catch {
    throw new Error('organization policy signature verification failed');
  }
  if (!validSignature)
    throw new Error('organization policy signature verification failed');
  const encodedPolicy = JSON.stringify(envelope.policy);
  if (encodedPolicy === undefined)
    throw new Error('organization policy payload is invalid');
  const loaded = parsePolicyAsCode(encodedPolicy);
  const sha256 = createHash('sha256')
    .update(canonicalJson(payload))
    .digest('hex');
  return {
    policy: loaded.policy,
    sha256,
    identity: `${envelope.issuer}:${envelope.keyId}:${sha256}`,
    issuer: envelope.issuer,
    keyId: envelope.keyId
  };
}

/** Parses policy bytes captured by the caller's immutable project snapshot. */
export function parsePolicyAsCode(source: string): {
  policy: PolicyAsCode;
  sha256: string;
} {
  if (Buffer.byteLength(source, 'utf8') > 1_048_576)
    throw new Error('policy file exceeds the size budget');
  const document = parseDocument(source, {
    uniqueKeys: true,
    prettyErrors: false
  });
  if (document.errors.length)
    throw new Error('policy document is malformed or contains duplicate keys');
  const parsed = policySchema.safeParse(document.toJS());
  if (!parsed.success)
    throw new Error(
      'policy document does not match the supported versioned schema'
    );
  return {
    policy: parsed.data,
    sha256: createHash('sha256').update(source).digest('hex')
  };
}

function compileGlob(pattern: string): RegExp | undefined {
  if (!isSafeSuppressionPattern(pattern)) return undefined;
  const expression = pattern
    .replace(/[.+^${}()|[\]\\]/gu, '\\$&')
    .replaceAll('**', '\u0000')
    .replaceAll('*', '[^/]*')
    .replaceAll('\u0000', '.*');
  return new RegExp(`^${expression}$`, 'u');
}

/**
 * Evaluates policy without conflating incomplete scans with clean results.
 * Privileged suppressions are honored only when the supplied policy source is
 * explicitly trusted; untrusted repository policy can still set thresholds.
 */
export function evaluatePolicyAsCode(input: {
  policy: PolicyAsCode;
  trust: PolicyTrust;
  findings: readonly Finding[];
  analysisState: AnalysisState;
  minimumSeverity?: FindingSeverity;
  coverage?: { eligible: number; scanned: number };
  now?: Date;
}): PolicyEvaluation {
  const { policy, trust, findings } = input;
  const order: Record<FindingSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  };
  const configuredMinimumSeverity = policy.minimumSeverity ?? 'high';
  const requestedMinimumSeverity = input.minimumSeverity;
  // A trusted organization gate may be strengthened by the caller, never
  // weakened by a local --fail-on override.
  const effectiveMinimumSeverity = trust.trusted
    ? order[requestedMinimumSeverity ?? configuredMinimumSeverity] >=
      order[configuredMinimumSeverity]
      ? (requestedMinimumSeverity ?? configuredMinimumSeverity)
      : configuredMinimumSeverity
    : (requestedMinimumSeverity ?? configuredMinimumSeverity);
  const minimum = order[effectiveMinimumSeverity];
  const kept: Finding[] = [];
  const suppressed: string[] = [];
  const selectedRuleSets = policy.ruleSets ?? ['all'];
  const categories = new Set(
    selectedRuleSets.flatMap((ruleSet) => ruleSetCategories[ruleSet])
  );
  const selectedFindings = findings.filter(
    (finding) => categories.has('*') || categories.has(finding.category)
  );
  const now = (input.now ?? new Date()).getTime();
  const expiredSuppressions = policy.suppressions
    .filter((suppression) => Date.parse(suppression.expiresAt) <= now)
    .map((suppression) => suppression.id);
  const suppressionsByRule = new Map<
    string,
    Array<{
      id: string;
      path?: string;
      pathRegex?: RegExp;
    }>
  >();
  for (const suppression of policy.suppressions) {
    if (Date.parse(suppression.expiresAt) <= now) continue;
    const entries = suppressionsByRule.get(suppression.ruleId) ?? [];
    entries.push({
      id: suppression.id,
      ...(suppression.path
        ? { path: suppression.path, pathRegex: compileGlob(suppression.path) }
        : {})
    });
    suppressionsByRule.set(suppression.ruleId, entries);
  }
  const isKnownExploited = (finding: Finding): boolean =>
    finding.category === 'vulnerability' &&
    (finding.metadata?.exploitIntel as { knownExploited?: unknown } | undefined)
      ?.knownExploited === true;
  const blockedKnownExploited =
    policy.blockKnownExploited === true &&
    selectedFindings.some(isKnownExploited);
  for (const finding of selectedFindings) {
    if (policy.blockKnownExploited === true && isKnownExploited(finding)) {
      kept.push(finding);
      continue;
    }
    const rule = policy.rules[finding.ruleId];
    if (rule?.enabled === false && trust.trusted) continue;
    const file = finding.location?.file ?? '';
    const expires = trust.trusted
      ? (suppressionsByRule.get(finding.ruleId) ?? []).find(
          (item) =>
            item.path === undefined || Boolean(item.pathRegex?.test(file))
        )
      : undefined;
    if (expires && trust.trusted) {
      suppressed.push(expires.id);
      continue;
    }
    const requested = rule?.severity;
    const adjustedSeverity =
      requested &&
      (trust.trusted || order[requested] <= order[finding.severity])
        ? requested
        : finding.severity;
    const adjusted = { ...finding, severity: adjustedSeverity };
    if (order[adjusted.severity] <= minimum) kept.push(adjusted);
  }
  const measuredCoverage = input.coverage
    ? input.coverage.eligible === 0
      ? 1
      : input.coverage.scanned / input.coverage.eligible
    : undefined;
  const coverageBelowMinimum =
    policy.minimumCoverage !== undefined &&
    (measuredCoverage === undefined ||
      measuredCoverage < policy.minimumCoverage);
  const decision: PolicyDecision =
    expiredSuppressions.length > 0
      ? 'misconfigured'
      : input.analysisState !== 'complete' || coverageBelowMinimum
        ? 'incomplete'
        : kept.length > 0 || blockedKnownExploited
          ? 'fail'
          : 'pass';
  const reasons =
    expiredSuppressions.length > 0
      ? [
          `policy contains expired suppression(s): ${expiredSuppressions.join(', ')}`
        ]
      : input.analysisState !== 'complete' || coverageBelowMinimum
        ? [
            input.analysisState !== 'complete'
              ? 'analysis coverage is incomplete; policy cannot pass'
              : `measured coverage ${measuredCoverage ?? 'unknown'} is below policy minimum ${policy.minimumCoverage}`
          ]
        : kept.length > 0
          ? [
              ...(blockedKnownExploited
                ? [
                    'one or more findings are listed in CISA KEV and blockKnownExploited is enabled'
                  ]
                : []),
              `${kept.length} finding(s) meet the policy threshold`
            ]
          : [];
  return Object.freeze({
    decision,
    findings: Object.freeze(kept),
    suppressed: Object.freeze(suppressed),
    policySha256: createHash('sha256')
      .update(
        canonicalJson({
          policy,
          effectiveMinimumSeverity,
          trust: trust.trusted
            ? { source: trust.source, identity: trust.identity ?? null }
            : { source: trust.source, identity: null }
        })
      )
      .digest('hex'),
    reasons: Object.freeze(reasons)
  });
}
