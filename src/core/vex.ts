import { createHash, randomUUID } from 'node:crypto';
import type { Finding } from '../contracts/finding.js';
import { npmPurl } from './sbom/generate.js';

export const vexStatuses = [
  'affected',
  'not_affected',
  'under_investigation',
  'fixed'
] as const;
export type VexStatus = (typeof vexStatuses)[number];
export type VexFormat = 'openvex' | 'cyclonedx';

const validJustifications = new Set([
  'component_not_present',
  'inline_mitigations_already_exist',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'protected_by_compiler_or_runtime',
  'protected_at_runtime',
  'protected_by_mitigating_control',
  'code_not_present',
  'code_not_reachable',
  'requires_configuration',
  'requires_dependency',
  'requires_environment'
]);
const maxStatements = 50_000;
const maxAssessmentValidityMs = 365 * 24 * 60 * 60 * 1000;

export type VexAssessment = {
  vulnerabilityId: string;
  subjectPurl: string;
  status: VexStatus;
  authority: string;
  assessedAt: string;
  expiresAt?: string;
  justification?: string;
  evidence?: string;
  actionStatement?: string;
};

export type VexApplicationResult = {
  findings: Finding[];
  applied: number;
  rejected: Array<{ vulnerabilityId: string; reason: string }>;
};

export function packageInstancePurl(input: {
  ecosystem: string;
  name: string;
  version: string;
  installPath?: string;
}): string {
  const version = encodeURIComponent(input.version);
  let base: string;
  switch (input.ecosystem) {
    case 'npm': {
      base = npmPurl(input.name, input.version);
      break;
    }
    case 'PyPI':
      base = `pkg:pypi/${encodeURIComponent(input.name.toLowerCase().replace(/[-_.]+/gu, '-'))}@${version}`;
      break;
    case 'Go':
      base = `pkg:golang/${input.name.split('/').map(encodeURIComponent).join('/')}@${version}`;
      break;
    case 'crates.io':
      base = `pkg:cargo/${encodeURIComponent(input.name)}@${version}`;
      break;
    case 'Maven': {
      const [group, artifact] = input.name.split(':');
      base = `pkg:maven/${encodeURIComponent(group ?? '')}/${encodeURIComponent(artifact ?? input.name)}@${version}`;
      break;
    }
    case 'Packagist':
      base = `pkg:composer/${input.name.split('/').map(encodeURIComponent).join('/')}@${version}`;
      break;
    default:
      throw new Error(`Unsupported VEX ecosystem: ${input.ecosystem}`);
  }
  return input.installPath
    ? `${base}?toolip_install_path=${encodeURIComponent(input.installPath)}`
    : base;
}

export function exportOpenVex(
  findings: Finding[],
  options: { author: string; timestamp?: string }
): Record<string, unknown> {
  const timestamp = options.timestamp ?? new Date().toISOString();
  assertAuthor(options.author);
  assertTimestamp(timestamp);
  const statements = exportableFindings(findings).flatMap(
    ({ finding, subjectPurl, vulnerabilityId }) => ({
      vulnerability: { '@id': vulnerabilityId },
      products: [{ '@id': subjectPurl }],
      status: 'affected',
      timestamp,
      last_updated: timestamp,
      'x-toolip-authority': options.author,
      'x-toolip-assessed-at': timestamp,
      action_statement: finding.remediation?.summary
    })
  );
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:toolip:vex:${hashJson(statements)}`,
    author: options.author,
    role: 'Document Creator',
    timestamp,
    version: 1,
    statements
  };
}

export function exportCycloneDxVex(
  findings: Finding[],
  options: { author: string; timestamp?: string }
): Record<string, unknown> {
  const timestamp = options.timestamp ?? new Date().toISOString();
  assertAuthor(options.author);
  assertTimestamp(timestamp);
  const records = exportableFindings(findings);
  const components = new Map<
    string,
    {
      'bom-ref': string;
      type: 'library';
      name: string;
      version: string;
      purl: string;
    }
  >();
  const vulnerabilities = new Map<string, Record<string, unknown>>();
  for (const {
    finding,
    subjectPurl,
    name,
    version,
    vulnerabilityId
  } of records) {
    const ref = `urn:toolip:instance:${hashText(subjectPurl)}`;
    components.set(ref, {
      'bom-ref': ref,
      type: 'library',
      name,
      version,
      purl: subjectPurl
    });
    {
      const id = vulnerabilityId;
      const current = vulnerabilities.get(id) ?? {
        id,
        source: { name: 'OSV.dev' },
        analysis: {
          state: 'exploitable',
          detail:
            'OSV reports this exact resolved package instance as affected.',
          firstIssued: timestamp,
          lastUpdated: timestamp
        },
        affects: [] as Array<Record<string, unknown>>,
        ratings: [
          {
            severity:
              finding.severity === 'info' ? 'informational' : finding.severity
          }
        ],
        recommendation: finding.remediation?.summary,
        properties: [
          { name: 'toolip:authority', value: options.author },
          { name: 'toolip:assessedAt', value: timestamp }
        ]
      };
      (current.affects as Array<Record<string, unknown>>).push({
        ref,
        versions: [{ version, status: 'affected' }]
      });
      vulnerabilities.set(id, current);
    }
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: 'Toolip', name: 'toolip' }]
    },
    components: [...components.values()],
    vulnerabilities: [...vulnerabilities.values()].sort((a, b) =>
      String(a.id).localeCompare(String(b.id))
    )
  };
}

export function parseVexDocument(
  input: unknown,
  format: VexFormat
): VexAssessment[] {
  if (!input || typeof input !== 'object')
    throw new Error('VEX document must be a JSON object.');
  const assessments =
    format === 'openvex'
      ? parseOpenVex(input as Record<string, unknown>)
      : parseCycloneDx(input as Record<string, unknown>);
  const unique = new Map<string, VexAssessment>();
  for (const assessment of assessments) {
    const key = assessmentKey(
      assessment.vulnerabilityId,
      assessment.subjectPurl
    );
    const current = unique.get(key);
    if (current && JSON.stringify(current) !== JSON.stringify(assessment)) {
      throw new Error(
        'VEX document contains conflicting assessments for one product.'
      );
    }
    unique.set(key, assessment);
  }
  return [...unique.values()].sort((left, right) =>
    assessmentKey(left.vulnerabilityId, left.subjectPurl).localeCompare(
      assessmentKey(right.vulnerabilityId, right.subjectPurl)
    )
  );
}

export function applyVexAssessments(
  findings: Finding[],
  assessments: VexAssessment[],
  options: { trustedAuthorities?: string[]; now?: Date } = {}
): VexApplicationResult {
  const trusted = new Set(options.trustedAuthorities ?? []);
  const now = options.now ?? new Date();
  const byKey = new Map<string, VexAssessment>();
  for (const assessment of assessments) {
    byKey.set(
      assessmentKey(assessment.vulnerabilityId, assessment.subjectPurl),
      assessment
    );
  }
  let applied = 0;
  const rejected: VexApplicationResult['rejected'] = [];
  const output = findings.map((finding) => {
    const identity = findingIdentity(finding);
    if (!identity) return finding;
    const candidates = identity.vulnerabilityIds
      .map((id) => byKey.get(assessmentKey(id, identity.subjectPurl)))
      .filter((value): value is VexAssessment => value !== undefined);
    if (candidates.length > 1) {
      const uniqueCandidates = new Set(
        candidates.map((item) => JSON.stringify(item))
      );
      if (uniqueCandidates.size > 1) {
        rejected.push({
          vulnerabilityId: identity.vulnerabilityId,
          reason: 'conflicting VEX assessments matched vulnerability aliases'
        });
        return finding;
      }
    }
    const assessment = candidates[0];
    if (!assessment) return finding;
    const denial = validateAssessment(assessment, trusted, now);
    if (denial) {
      rejected.push({
        vulnerabilityId: assessment.vulnerabilityId,
        reason: denial
      });
      return finding;
    }
    applied++;
    return {
      ...finding,
      metadata: {
        ...finding.metadata,
        vexAssessment: {
          status: assessment.status,
          authority: assessment.authority,
          assessedAt: assessment.assessedAt,
          expiresAt: assessment.expiresAt,
          justification: assessment.justification,
          evidence: assessment.evidence,
          actionStatement: assessment.actionStatement
        }
      }
    };
  });
  return { findings: output, applied, rejected };
}

function parseOpenVex(document: Record<string, unknown>): VexAssessment[] {
  if (
    document['@context'] !== 'https://openvex.dev/ns/v0.2.0' ||
    document.version !== 1 ||
    !isTimestamp(document.timestamp) ||
    typeof document.author !== 'string' ||
    document.author.length === 0 ||
    !Array.isArray(document.statements) ||
    document.statements.length > maxStatements
  ) {
    throw new Error('OpenVEX document has an unsupported or invalid schema.');
  }
  const output: VexAssessment[] = [];
  for (const statement of document.statements) {
    if (!statement || typeof statement !== 'object')
      throw new Error('OpenVEX statement is malformed.');
    const row = statement as Record<string, unknown>;
    const vulnerability = row.vulnerability as
      Record<string, unknown> | undefined;
    const products = row.products as Array<Record<string, unknown>> | undefined;
    const status = normalizeStatus(row.status);
    const assessedAt = stringOr(
      row['x-toolip-assessed-at'],
      document.timestamp as string
    );
    const authority = stringOr(
      row['x-toolip-authority'],
      document.author as string
    );
    const expiresAt = row['x-toolip-expires-at'];
    if (
      typeof vulnerability?.['@id'] !== 'string' ||
      vulnerability['@id'].length > 512 ||
      !Array.isArray(products) ||
      products.length === 0 ||
      products.length > 1000
    ) {
      throw new Error(
        'OpenVEX statement has an invalid vulnerability or product.'
      );
    }
    for (const product of products) {
      if (typeof product['@id'] !== 'string' || !validPurl(product['@id']))
        throw new Error('OpenVEX product identifier must be a package URL.');
      output.push({
        vulnerabilityId: vulnerability['@id'] as string,
        subjectPurl: product['@id'],
        status,
        authority,
        assessedAt,
        ...(typeof expiresAt === 'string' ? { expiresAt } : {}),
        ...(typeof row.justification === 'string'
          ? { justification: row.justification }
          : {}),
        ...(typeof row.impact_statement === 'string'
          ? { evidence: row.impact_statement.slice(0, 2048) }
          : {}),
        ...(typeof row.action_statement === 'string'
          ? { actionStatement: row.action_statement.slice(0, 2048) }
          : {})
      });
      if (output.length > maxStatements)
        throw new Error('OpenVEX document exceeds the assessment limit.');
    }
  }
  return output;
}

function parseCycloneDx(document: Record<string, unknown>): VexAssessment[] {
  if (
    document.bomFormat !== 'CycloneDX' ||
    !['1.5', '1.6'].includes(String(document.specVersion)) ||
    !isTimestamp(
      (document.metadata as Record<string, unknown> | undefined)?.timestamp
    ) ||
    !Array.isArray(document.vulnerabilities) ||
    document.vulnerabilities.length > maxStatements
  ) {
    throw new Error(
      'CycloneDX VEX document has an unsupported or invalid schema.'
    );
  }
  const components = new Map<string, { purl: string; version: string }>();
  if (Array.isArray(document.components)) {
    for (const component of document.components) {
      if (!component || typeof component !== 'object') continue;
      const row = component as Record<string, unknown>;
      if (
        typeof row['bom-ref'] === 'string' &&
        typeof row.purl === 'string' &&
        validPurl(row.purl) &&
        typeof row.version === 'string'
      ) {
        components.set(row['bom-ref'], {
          purl: row.purl,
          version: row.version
        });
      }
    }
  }
  const documentTimestamp = (document.metadata as Record<string, unknown>)
    .timestamp as string;
  const output: VexAssessment[] = [];
  for (const value of document.vulnerabilities) {
    if (!value || typeof value !== 'object')
      throw new Error('CycloneDX VEX vulnerability is malformed.');
    const row = value as Record<string, unknown>;
    if (typeof row.id !== 'string' || !Array.isArray(row.affects))
      throw new Error('CycloneDX VEX vulnerability has an invalid identity.');
    const analysis = row.analysis as Record<string, unknown> | undefined;
    const properties = Array.isArray(row.properties) ? row.properties : [];
    const authority =
      propertyValue(properties, 'toolip:authority') ??
      (row.source &&
      typeof row.source === 'object' &&
      typeof (row.source as Record<string, unknown>).name === 'string'
        ? String((row.source as Record<string, unknown>).name)
        : '');
    const expiresAt = propertyValue(properties, 'toolip:validUntil');
    const assessedAt =
      propertyValue(properties, 'toolip:assessedAt') ??
      (typeof analysis?.lastUpdated === 'string'
        ? analysis.lastUpdated
        : documentTimestamp);
    const status = normalizeCycloneStatus(analysis?.state);
    const justification =
      typeof analysis?.justification === 'string'
        ? analysis.justification
        : undefined;
    for (const affect of row.affects) {
      if (!affect || typeof affect !== 'object') continue;
      const target = affect as Record<string, unknown>;
      const component =
        typeof target.ref === 'string' ? components.get(target.ref) : undefined;
      const affectedPurl =
        component?.purl ??
        (typeof target.ref === 'string' && validPurl(target.ref)
          ? target.ref
          : undefined);
      if (!affectedPurl) continue;
      output.push({
        vulnerabilityId: row.id,
        subjectPurl: affectedPurl,
        status,
        authority,
        assessedAt,
        ...(expiresAt ? { expiresAt } : {}),
        ...(justification ? { justification } : {}),
        ...(typeof analysis?.detail === 'string'
          ? { evidence: analysis.detail.slice(0, 2048) }
          : {})
      });
      if (output.length > maxStatements)
        throw new Error('CycloneDX VEX document exceeds the assessment limit.');
    }
  }
  return output;
}

function exportableFindings(findings: Finding[]): Array<{
  finding: Finding;
  subjectPurl: string;
  name: string;
  version: string;
  vulnerabilityId: string;
  vulnerabilityIds: string[];
}> {
  const output = findings.flatMap((finding) => {
    const identity = findingIdentity(finding);
    if (!identity) return [];
    return [{ ...identity, finding }];
  });
  if (output.length > maxStatements) {
    throw new Error('VEX export exceeds the statement limit.');
  }
  return output;
}

function findingIdentity(finding: Finding):
  | {
      vulnerabilityId: string;
      vulnerabilityIds: string[];
      subjectPurl: string;
      name: string;
      version: string;
    }
  | undefined {
  const metadata = finding.metadata ?? {};
  const name = metadata.package;
  const version = metadata.installedVersion ?? metadata.version;
  const ecosystem = metadata.ecosystem;
  const installPath = metadata.installPath;
  const primaryId = metadata.vulnerabilityId;
  if (
    typeof name !== 'string' ||
    typeof version !== 'string' ||
    typeof ecosystem !== 'string' ||
    typeof primaryId !== 'string'
  )
    return undefined;
  try {
    return {
      vulnerabilityId: primaryId,
      vulnerabilityIds: [
        ...new Set([
          primaryId,
          ...(Array.isArray(metadata.aliases)
            ? metadata.aliases.filter(
                (alias): alias is string => typeof alias === 'string'
              )
            : [])
        ])
      ].sort(),
      subjectPurl: packageInstancePurl({
        ecosystem,
        name,
        version,
        ...(typeof installPath === 'string' ? { installPath } : {})
      }),
      name,
      version
    };
  } catch {
    return undefined;
  }
}

function assertAuthor(author: string): void {
  if (
    !author.trim() ||
    author.length > 256 ||
    author.includes('\r') ||
    author.includes('\n') ||
    [...author].some((character) => character.charCodeAt(0) < 32)
  )
    throw new Error('VEX author must be a short, non-empty single-line value.');
}

function assertTimestamp(timestamp: string): void {
  if (!isTimestamp(timestamp))
    throw new Error('VEX timestamp must be a valid UTC RFC 3339 timestamp.');
}

function normalizeStatus(value: unknown): VexStatus {
  if (vexStatuses.includes(value as VexStatus)) return value as VexStatus;
  throw new Error('VEX statement has an unsupported status.');
}

function normalizeCycloneStatus(value: unknown): VexStatus {
  switch (value) {
    case 'exploitable':
      return 'affected';
    case 'not_affected':
      return 'not_affected';
    case 'resolved':
      return 'fixed';
    case 'in_triage':
    case undefined:
      return 'under_investigation';
    default:
      throw new Error('CycloneDX VEX contains an unsupported analysis state.');
  }
}

function validateAssessment(
  assessment: VexAssessment,
  trusted: Set<string>,
  now: Date
): string | undefined {
  if (!trusted.has(assessment.authority)) return 'authority is not trusted';
  if (!isTimestamp(assessment.assessedAt))
    return 'assessment timestamp is invalid';
  if (Date.parse(assessment.assessedAt) > now.getTime())
    return 'assessment timestamp is in the future';
  if (assessment.expiresAt !== undefined) {
    if (!isTimestamp(assessment.expiresAt))
      return 'assessment expiry is invalid';
    if (Date.parse(assessment.expiresAt) <= now.getTime())
      return 'assessment has expired';
    if (Date.parse(assessment.expiresAt) <= Date.parse(assessment.assessedAt))
      return 'assessment expiry precedes its timestamp';
  }
  if (assessment.status !== 'not_affected') return undefined;
  if (
    !assessment.justification ||
    !validJustifications.has(assessment.justification)
  ) {
    return 'not_affected status requires a recognized justification';
  }
  if (!assessment.evidence?.trim() || assessment.evidence.length > 2048)
    return 'not_affected status requires a concise evidence statement';
  if (!assessment.expiresAt)
    return 'not_affected status requires a valid expiry';
  if (
    Date.parse(assessment.expiresAt) - Date.parse(assessment.assessedAt) >
    maxAssessmentValidityMs
  ) {
    return 'not_affected expiry must be within one year of assessment';
  }
  return undefined;
}

function validPurl(value: string): boolean {
  return (
    value.length <= 2048 &&
    /^pkg:[a-z0-9.+-]+\/[A-Za-z0-9%._~!$&'()*+,;=:@/-]+@[A-Za-z0-9%._~!$&'()*+,;=:@/-]+(?:\?[A-Za-z0-9%._~!$&'()*+,;=:@/?-]+)?$/u.test(
      value
    )
  );
}

function isTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function propertyValue(
  properties: unknown[],
  name: string
): string | undefined {
  for (const property of properties) {
    if (!property || typeof property !== 'object') continue;
    const row = property as Record<string, unknown>;
    if (row.name === name && typeof row.value === 'string') return row.value;
  }
  return undefined;
}

function hashText(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 24);
}

function hashJson(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function assessmentKey(vulnerabilityId: string, purl: string): string {
  return `${vulnerabilityId.toUpperCase()}\0${purl}`;
}
