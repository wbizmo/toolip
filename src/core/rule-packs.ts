import { constants } from 'node:fs';
import { createHash, verify as cryptoVerify } from 'node:crypto';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import type {
  Finding,
  FindingConfidence,
  FindingSeverity
} from '../contracts/finding.js';
import { canonicalEvidenceJson } from './report-signature.js';
import { readPemKeyFile } from './secure-key-file.js';

const MAX_RULE_PACK_BYTES = 1024 * 1024;
const MAX_RULES = 256;
const MAX_RULE_PACKS_PER_SCAN = 16;
const MAX_TOTAL_RULES_PER_SCAN = 512;
const MAX_CUSTOM_FINDINGS_PER_SCAN = 10_000;
const MAX_LITERAL_LENGTH = 256;
const MAX_RULE_PACK_LIFETIME_MS = 180 * 24 * 60 * 60 * 1000;
const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
const verifiedRulePacks = new WeakSet<VerifiedRulePack>();

export type DeclarativeRulePackRule = Readonly<{
  id: string;
  title: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  literal: string;
  fileExtensions: readonly string[];
  remediation: string;
}>;

export type VerifiedRulePack = Readonly<{
  id: string;
  apiVersion: 1;
  issuedAt: string;
  expiresAt: string;
  keyId?: string;
  trust: 'signature' | 'unsigned-local-override';
  sha256: string;
  rules: readonly DeclarativeRulePackRule[];
}>;

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[]
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function safeText(value: unknown, maxLength: number): value is string {
  return (
    typeof value === 'string' &&
    value.trim() === value &&
    value.length > 0 &&
    value.length <= maxLength &&
    !Array.from(value).some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  );
}

function readTimestamp(value: unknown): number | undefined {
  if (typeof value !== 'string') return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value
    ? time
    : undefined;
}

async function readRulePackFile(filePath: string): Promise<string> {
  const absolute = path.resolve(filePath);
  const named = await lstat(absolute);
  if (named.isSymbolicLink() || !named.isFile())
    throw new Error('Rule pack path must be a regular, non-symlink file.');
  if (named.size === 0 || named.size > MAX_RULE_PACK_BYTES)
    throw new Error('Rule pack is empty or exceeds the size limit.');
  const handle = await open(
    absolute,
    constants.O_RDONLY |
      noFollow |
      (process.platform === 'win32' ? 0 : constants.O_NONBLOCK)
  );
  try {
    const opened = await handle.stat();
    const after = await lstat(absolute);
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      opened.dev !== after.dev ||
      opened.ino !== after.ino ||
      opened.size > MAX_RULE_PACK_BYTES
    )
      throw new Error('Rule pack changed while it was being opened.');
    const chunks: Buffer[] = [];
    let size = 0;
    while (size <= MAX_RULE_PACK_BYTES) {
      const chunk = Buffer.alloc(
        Math.min(64 * 1024, MAX_RULE_PACK_BYTES + 1 - size)
      );
      const result = await handle.read(chunk, 0, chunk.length, null);
      if (result.bytesRead === 0) break;
      size += result.bytesRead;
      if (size > MAX_RULE_PACK_BYTES)
        throw new Error('Rule pack exceeds the size limit.');
      chunks.push(chunk.subarray(0, result.bytesRead));
    }
    const finalStat = await handle.stat();
    if (
      size === 0 ||
      finalStat.size !== opened.size ||
      finalStat.mtimeMs !== opened.mtimeMs ||
      finalStat.ctimeMs !== opened.ctimeMs
    )
      throw new Error('Rule pack is empty or changed while it was read.');
    const bytes = Buffer.concat(chunks, size);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } finally {
    await handle.close();
  }
}

/** Loads a bounded, declarative pack. It never imports or executes pack code. */
export async function loadRulePackFile(
  filePath: string,
  options: {
    publicKeyPem?: string;
    trustedKeyId?: string;
    allowUnsignedLocalOverride?: boolean;
    now?: number;
  } = {}
): Promise<VerifiedRulePack> {
  const text = await readRulePackFile(filePath);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Rule pack JSON is invalid.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    throw new Error('Rule pack must be a JSON object.');
  const value = parsed as Record<string, unknown>;
  if (
    !exactKeys(value, [
      'schema',
      'id',
      'apiVersion',
      'issuedAt',
      'expiresAt',
      'rules',
      'signature'
    ]) ||
    value.schema !== 'toolip.dev/rule-pack/v1' ||
    value.apiVersion !== 1 ||
    typeof value.id !== 'string' ||
    !/^[a-z][a-z0-9]{1,15}$/u.test(value.id) ||
    !Array.isArray(value.rules) ||
    value.rules.length === 0 ||
    value.rules.length > MAX_RULES
  )
    throw new Error('Rule pack manifest is invalid or unsupported.');

  const now = options.now ?? Date.now();
  const issuedAt = readTimestamp(value.issuedAt);
  const expiresAt = readTimestamp(value.expiresAt);
  if (
    issuedAt === undefined ||
    expiresAt === undefined ||
    issuedAt > now + 5 * 60 * 1000 ||
    expiresAt <= now ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > MAX_RULE_PACK_LIFETIME_MS
  )
    throw new Error('Rule pack is expired or has invalid validity dates.');

  const rules: DeclarativeRulePackRule[] = [];
  const ids = new Set<string>();
  for (const rawRule of value.rules) {
    if (!rawRule || typeof rawRule !== 'object' || Array.isArray(rawRule))
      throw new Error('Rule pack contains a malformed rule.');
    const rule = rawRule as Record<string, unknown>;
    const expectedPrefix = `TLP-${value.id.toUpperCase()}-`;
    if (
      !exactKeys(rule, [
        'id',
        'title',
        'severity',
        'confidence',
        'literal',
        'fileExtensions',
        'remediation'
      ]) ||
      typeof rule.id !== 'string' ||
      !new RegExp(`^${expectedPrefix}\\d{3}$`, 'u').test(rule.id) ||
      ids.has(rule.id) ||
      !safeText(rule.title, 160) ||
      !['critical', 'high', 'medium', 'low', 'info'].includes(
        String(rule.severity)
      ) ||
      !['high', 'medium', 'low'].includes(String(rule.confidence)) ||
      typeof rule.literal !== 'string' ||
      rule.literal.length < 3 ||
      rule.literal.length > MAX_LITERAL_LENGTH ||
      !Array.isArray(rule.fileExtensions) ||
      rule.fileExtensions.length > 32 ||
      rule.fileExtensions.some(
        (extension) =>
          typeof extension !== 'string' ||
          !/^\.[a-z0-9]{1,12}$/u.test(extension)
      ) ||
      !safeText(rule.remediation, 512)
    )
      throw new Error('Rule pack contains an invalid or unsafe rule.');
    ids.add(rule.id);
    rules.push(
      Object.freeze({
        id: rule.id,
        title: rule.title,
        severity: rule.severity as FindingSeverity,
        confidence: rule.confidence as FindingConfidence,
        literal: rule.literal,
        fileExtensions: Object.freeze(
          [...new Set(rule.fileExtensions as string[])].sort()
        ),
        remediation: rule.remediation
      })
    );
  }

  let keyId: string | undefined;
  let trust: VerifiedRulePack['trust'];
  if (value.signature === undefined) {
    if (options.allowUnsignedLocalOverride !== true)
      throw new Error('Unsigned rule packs are denied by default.');
    trust = 'unsigned-local-override';
  } else {
    if (
      !value.signature ||
      typeof value.signature !== 'object' ||
      Array.isArray(value.signature) ||
      !exactKeys(value.signature as Record<string, unknown>, [
        'algorithm',
        'keyId',
        'value'
      ])
    )
      throw new Error('Rule pack signature envelope is invalid.');
    const signature = value.signature as Record<string, unknown>;
    if (
      signature.algorithm !== 'Ed25519' ||
      typeof signature.keyId !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(signature.keyId) ||
      typeof signature.value !== 'string' ||
      !/^[A-Za-z0-9+/]{86}==$/u.test(signature.value) ||
      !options.publicKeyPem ||
      options.trustedKeyId !== signature.keyId
    )
      throw new Error('Rule pack signature key is not trusted.');
    const { signature: _discarded, ...payload } = value;
    const canonical = canonicalEvidenceJson(payload);
    let valid = false;
    try {
      valid = cryptoVerify(
        null,
        Buffer.from(canonical),
        options.publicKeyPem,
        Buffer.from(signature.value, 'base64')
      );
    } catch {
      throw new Error('Rule pack signature is malformed.');
    }
    if (!valid) throw new Error('Rule pack signature verification failed.');
    keyId = signature.keyId;
    trust = 'signature';
  }

  const { signature: _signature, ...payload } = value;
  const canonicalPayload = canonicalEvidenceJson(payload);
  const pack: VerifiedRulePack = Object.freeze({
    id: value.id,
    apiVersion: 1,
    issuedAt: value.issuedAt as string,
    expiresAt: value.expiresAt as string,
    ...(keyId ? { keyId } : {}),
    trust,
    sha256: createHash('sha256').update(canonicalPayload).digest('hex'),
    rules: Object.freeze(rules)
  });
  verifiedRulePacks.add(pack);
  return pack;
}

/** Resolves CLI trust options and denies stray flags without a selected pack. */
export async function loadRulePackForCli(options: {
  filePath?: string;
  publicKeyPath?: string;
  trustedKeyId?: string;
  allowUnsignedLocalOverride?: boolean;
}): Promise<VerifiedRulePack | undefined> {
  const trustOptionsPresent = Boolean(
    options.publicKeyPath ||
    options.trustedKeyId ||
    options.allowUnsignedLocalOverride
  );
  if (!options.filePath) {
    if (trustOptionsPresent)
      throw new Error('Rule-pack trust options require --rule-pack.');
    return undefined;
  }
  if (Boolean(options.publicKeyPath) !== Boolean(options.trustedKeyId))
    throw new Error(
      '--rule-pack-public-key and --rule-pack-key-id must be provided together.'
    );
  const publicKeyPem = options.publicKeyPath
    ? await readPemKeyFile(options.publicKeyPath)
    : undefined;
  return loadRulePackFile(options.filePath, {
    publicKeyPem,
    trustedKeyId: options.trustedKeyId,
    allowUnsignedLocalOverride: options.allowUnsignedLocalOverride
  });
}

/** Matches at most once per rule and file; match text never enters a finding. */
export function analyzeRulePacks(
  rulePacks: readonly VerifiedRulePack[],
  relativePath: string,
  content: string,
  maximumFindings = MAX_CUSTOM_FINDINGS_PER_SCAN
): Finding[] {
  assertRulePackScanLimits(rulePacks);
  const extension = path.extname(relativePath).toLowerCase();
  const findings: Finding[] = [];
  for (const pack of rulePacks) {
    if (findings.length >= maximumFindings) break;
    for (const rule of pack.rules) {
      if (
        rule.fileExtensions.length > 0 &&
        !rule.fileExtensions.includes(extension)
      )
        continue;
      const offset = content.indexOf(rule.literal);
      if (offset < 0) continue;
      if (findings.length >= maximumFindings) break;
      let line = 1;
      let lineStart = 0;
      for (let index = 0; index < offset; index++) {
        if (content.charCodeAt(index) === 10) {
          line++;
          lineStart = index + 1;
        }
      }
      const column = offset - lineStart + 1;
      const fingerprint = createHash('sha256')
        .update(`${pack.id}\0${rule.id}\0${relativePath}\0${line}\0${column}`)
        .digest('hex');
      findings.push({
        id: fingerprint,
        ruleId: rule.id,
        title: rule.title,
        category: 'custom-rule-pack',
        severity: rule.severity,
        confidence: rule.confidence,
        message: 'A configured literal matched; matched content is withheld.',
        source: `signed-rule-pack:${pack.id}`,
        location: { file: relativePath, line, column },
        evidence: [
          {
            summary: '[configured literal matched; source text redacted]',
            fingerprint
          }
        ],
        remediation: { summary: rule.remediation },
        metadata: {
          rulePackId: pack.id,
          rulePackSha256: pack.sha256,
          trust: pack.trust,
          ...(pack.keyId ? { keyId: pack.keyId } : {})
        }
      });
    }
  }
  return findings;
}

export function assertRulePackScanLimits(
  rulePacks: readonly VerifiedRulePack[]
): void {
  if (
    !Array.isArray(rulePacks) ||
    rulePacks.length > MAX_RULE_PACKS_PER_SCAN ||
    rulePacks.some(
      (pack) =>
        !pack ||
        typeof pack !== 'object' ||
        !verifiedRulePacks.has(pack) ||
        Date.parse(pack.expiresAt) <= Date.now()
    ) ||
    rulePacks.reduce((count, pack) => count + pack.rules.length, 0) >
      MAX_TOTAL_RULES_PER_SCAN
  )
    throw new Error(
      'Rule packs must be verified, current, and within the configured scan budget.'
    );
}

export const rulePackFindingBudget = MAX_CUSTOM_FINDINGS_PER_SCAN;
