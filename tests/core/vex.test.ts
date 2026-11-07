import { describe, expect, it } from 'vitest';
import type { Finding } from '../../src/contracts/finding.js';
import {
  applyVexAssessments,
  exportCycloneDxVex,
  exportOpenVex,
  packageInstancePurl,
  parseVexDocument
} from '../../src/core/vex.js';

function vulnerabilityFinding(installPath = 'node_modules/example'): Finding {
  return {
    id: 'TLP-CVE-EXAMPLE',
    ruleId: 'TLP-CVE-001',
    title: 'Vulnerable package instance',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'high',
    message: 'Resolved package matches an advisory.',
    source: 'osv',
    evidence: [{ summary: 'Exact installed identity matched.' }],
    remediation: { summary: 'Upgrade to 2.0.0.', fixedVersion: '2.0.0' },
    metadata: {
      package: '@scope/example',
      ecosystem: 'npm',
      installedVersion: '1.0.0',
      installPath,
      vulnerabilityId: 'GHSA-test-0001',
      aliases: ['CVE-2026-12345']
    }
  };
}

describe('CycloneDX and OpenVEX integration', () => {
  it('uses canonical npm and PEP 503 identifiers in VEX package URLs', () => {
    expect(
      packageInstancePurl({
        ecosystem: 'npm',
        name: '@scope/pkg:extra',
        version: '1.0.0+build'
      })
    ).toBe('pkg:npm/%40scope/pkg%3Aextra@1.0.0%2Bbuild');
    expect(
      packageInstancePurl({
        ecosystem: 'PyPI',
        name: 'My_Package.Name',
        version: '1.2.3'
      })
    ).toBe('pkg:pypi/my-package-name@1.2.3');
  });

  it('exports exact package-instance identities and round-trips OpenVEX aliases', () => {
    const finding = vulnerabilityFinding();
    const document = exportOpenVex([finding], {
      author: 'Toolip test authority',
      timestamp: '2026-11-06T12:00:00.000Z'
    });
    const assessments = parseVexDocument(document, 'openvex');

    expect(assessments).toHaveLength(1);
    expect(assessments[0]?.vulnerabilityId).toBe('GHSA-test-0001');
    expect(assessments[0]?.subjectPurl).toBe(
      'pkg:npm/%40scope/example@1.0.0?toolip_install_path=node_modules%2Fexample'
    );
    expect(
      packageInstancePurl({
        ecosystem: 'npm',
        name: '@scope/example',
        version: '1.0.0',
        installPath: 'node_modules/parent/node_modules/example'
      })
    ).not.toBe(assessments[0]?.subjectPurl);
  });

  it('exports CycloneDX 1.5 VEX with component refs that resolve to exact purls', () => {
    const document = exportCycloneDxVex(
      [
        vulnerabilityFinding(),
        vulnerabilityFinding('node_modules/parent/node_modules/example')
      ],
      {
        author: 'Toolip test authority',
        timestamp: '2026-11-06T12:00:00.000Z'
      }
    );
    const assessments = parseVexDocument(document, 'cyclonedx');

    expect(document).toMatchObject({
      bomFormat: 'CycloneDX',
      specVersion: '1.5'
    });
    expect((document.components as unknown[]).length).toBe(2);
    expect(assessments).toHaveLength(2);
    expect(
      new Set(assessments.map((assessment) => assessment.subjectPurl)).size
    ).toBe(2);
    expect(
      assessments.every((assessment) => assessment.status === 'affected')
    ).toBe(true);
  });

  it('requires trusted, evidence-backed, justified and unexpired not_affected assessments', () => {
    const finding = vulnerabilityFinding();
    const document = exportOpenVex([finding], {
      author: 'Trusted assessor',
      timestamp: '2026-11-06T10:00:00.000Z'
    });
    const statement = (
      document.statements as Array<Record<string, unknown>>
    )[0];
    expect(statement).toBeDefined();
    if (!statement) throw new Error('VEX document did not contain a statement');
    statement.status = 'not_affected';
    statement.justification = 'vulnerable_code_not_in_execute_path';
    statement.impact_statement =
      'Reviewed call paths show the vulnerable code is unreachable.';
    statement['x-toolip-expires-at'] = '2027-01-01T00:00:00.000Z';
    const assessments = parseVexDocument(document, 'openvex');

    const untrusted = applyVexAssessments([finding], assessments, {
      now: new Date('2026-11-06T12:00:00.000Z')
    });
    expect(untrusted.applied).toBe(0);
    expect(untrusted.rejected[0]?.reason).toBe('authority is not trusted');

    const trusted = applyVexAssessments([finding], assessments, {
      trustedAuthorities: ['Trusted assessor'],
      now: new Date('2026-11-06T12:00:00.000Z')
    });
    expect(trusted.applied).toBe(1);
    expect(trusted.findings).toHaveLength(1);
    expect(trusted.findings[0]?.metadata?.vexAssessment).toMatchObject({
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path'
    });
  });

  it('rejects expired or evidence-free assessments and conflicting alias decisions', () => {
    const finding = vulnerabilityFinding();
    const document = exportOpenVex([finding], {
      author: 'Trusted assessor',
      timestamp: '2026-11-06T10:00:00.000Z'
    });
    const original = (document.statements as Array<Record<string, unknown>>)[0];
    expect(original).toBeDefined();
    if (!original) throw new Error('VEX document did not contain a statement');
    original.status = 'not_affected';
    original.justification = 'component_not_present';
    original.impact_statement = 'The component is absent.';
    original['x-toolip-expires-at'] = '2026-11-01T00:00:00.000Z';
    const expired = applyVexAssessments(
      [finding],
      parseVexDocument(document, 'openvex'),
      {
        trustedAuthorities: ['Trusted assessor'],
        now: new Date('2026-11-06T12:00:00.000Z')
      }
    );
    expect(expired.applied).toBe(0);
    expect(expired.rejected[0]?.reason).toBe('assessment has expired');

    const conflicting = JSON.parse(JSON.stringify(document)) as Record<
      string,
      unknown
    >;
    (conflicting.statements as Array<Record<string, unknown>>).push({
      ...(conflicting.statements as Array<Record<string, unknown>>)[0],
      status: 'affected',
      vulnerability: { '@id': 'GHSA-test-0001' }
    });
    expect(() => parseVexDocument(conflicting, 'openvex')).toThrow(
      'conflicting assessments'
    );
  });

  it('rejects malformed formats, invalid products and oversized status claims', () => {
    expect(() => parseVexDocument({}, 'openvex')).toThrow(
      'unsupported or invalid schema'
    );
    expect(() =>
      parseVexDocument(
        {
          '@context': 'https://openvex.dev/ns/v0.2.0',
          author: 'tester',
          timestamp: '2026-11-06T12:00:00.000Z',
          version: 1,
          statements: [
            {
              vulnerability: { '@id': 'CVE-2026-12345' },
              products: [{ '@id': 'file:///etc/passwd' }],
              status: 'not_affected'
            }
          ]
        },
        'openvex'
      )
    ).toThrow('package URL');
  });
});
