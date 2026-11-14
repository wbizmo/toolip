import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import type { Finding } from '../../src/contracts/finding.js';
import {
  applyVexAssessments,
  exportCycloneDxVex,
  exportOpenVex,
  packageInstancePurl,
  parseVexDocument,
  signVexDocument
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

  it('rejects impossible timestamps and ambiguous CycloneDX component identities', () => {
    const impossibleTimestamp = exportOpenVex([vulnerabilityFinding()], {
      author: 'Toolip test authority',
      timestamp: '2026-11-06T12:00:00.000Z'
    });
    impossibleTimestamp.timestamp = '2026-02-31T12:00:00.000Z';
    expect(() => parseVexDocument(impossibleTimestamp, 'openvex')).toThrow(
      'unsupported or invalid schema'
    );

    const versionMismatch = exportCycloneDxVex([vulnerabilityFinding()], {
      author: 'Toolip test authority',
      timestamp: '2026-11-06T12:00:00.000Z'
    });
    const components = versionMismatch.components as Array<
      Record<string, unknown>
    >;
    const component = components[0];
    if (!component) throw new Error('CycloneDX component is missing');
    component.purl =
      'pkg:npm/%40scope/example@9.0.0?toolip_install_path=node_modules%2Fexample';
    expect(() => parseVexDocument(versionMismatch, 'cyclonedx')).toThrow(
      'version does not match'
    );

    const duplicateReference = exportCycloneDxVex([vulnerabilityFinding()], {
      author: 'Toolip test authority',
      timestamp: '2026-11-06T12:00:00.000Z'
    });
    const duplicateComponents = duplicateReference.components as Array<
      Record<string, unknown>
    >;
    duplicateComponents.push(structuredClone(duplicateComponents[0]));
    expect(() => parseVexDocument(duplicateReference, 'cyclonedx')).toThrow(
      'duplicate component reference'
    );
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
    const keys = generateKeyPairSync('ed25519');
    const signed = signVexDocument(
      document,
      'openvex',
      keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      'security-team-2026'
    );
    const assessments = parseVexDocument(signed, 'openvex', {
      trustedPublicKeyPem: keys.publicKey
        .export({ type: 'spki', format: 'pem' })
        .toString(),
      trustedKeyId: 'security-team-2026'
    });

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
    expect(trusted.findings).toHaveLength(0);
    expect(trusted.suppressed).toHaveLength(1);
    expect(trusted.suppressed[0]?.metadata?.vexAssessment).toMatchObject({
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path'
    });
    const otherInstance = applyVexAssessments(
      [vulnerabilityFinding('node_modules/parent/node_modules/example')],
      assessments,
      {
        trustedAuthorities: ['Trusted assessor'],
        now: new Date('2026-11-06T12:00:00.000Z')
      }
    );
    expect(otherInstance.applied).toBe(0);
    expect(otherInstance.findings).toHaveLength(1);
    expect(otherInstance.suppressed).toHaveLength(0);
  });

  it('does not suppress a finding based on preexisting untrusted metadata', () => {
    const finding = vulnerabilityFinding();
    finding.metadata = {
      ...finding.metadata,
      vexAssessment: { status: 'not_affected', authority: 'untrusted' }
    };

    const result = applyVexAssessments([finding], [], {
      trustedAuthorities: ['Trusted assessor'],
      now: new Date('2026-11-06T12:00:00.000Z')
    });

    expect(result.applied).toBe(0);
    expect(result.findings).toEqual([finding]);
    expect(result.suppressed).toHaveLength(0);
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
    const keys = generateKeyPairSync('ed25519');
    const signed = signVexDocument(
      document,
      'openvex',
      keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      'security-team-2026'
    );
    const expired = applyVexAssessments(
      [finding],
      parseVexDocument(signed, 'openvex', {
        trustedPublicKeyPem: keys.publicKey
          .export({ type: 'spki', format: 'pem' })
          .toString(),
        trustedKeyId: 'security-team-2026'
      }),
      {
        trustedAuthorities: ['Trusted assessor'],
        now: new Date('2026-11-06T12:00:00.000Z')
      }
    );
    expect(expired.applied).toBe(0);
    expect(expired.findings).toHaveLength(1);
    expect(expired.suppressed).toHaveLength(0);
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

  it('does not trust a forged authority name or accept tampered signed content', () => {
    const finding = vulnerabilityFinding();
    const document = exportOpenVex([finding], {
      author: 'Trusted assessor',
      timestamp: '2026-11-06T10:00:00.000Z'
    });
    const statement = (
      document.statements as Array<Record<string, unknown>>
    )[0];
    if (!statement) throw new Error('VEX fixture is missing its statement');
    statement.status = 'not_affected';
    statement.justification = 'vulnerable_code_not_in_execute_path';
    statement.impact_statement = 'Assessment evidence from the trusted team.';
    statement['x-toolip-expires-at'] = '2027-01-01T00:00:00.000Z';

    const unsigned = applyVexAssessments(
      [finding],
      parseVexDocument(document, 'openvex'),
      { trustedAuthorities: ['Trusted assessor'] }
    );
    expect(unsigned.applied).toBe(0);
    expect(unsigned.rejected[0]?.reason).toBe(
      'not_affected assessment is not signed by a trusted key'
    );

    const keys = generateKeyPairSync('ed25519');
    const signed = signVexDocument(
      document,
      'openvex',
      keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      'security-team-2026'
    );
    const signedStatement = (
      signed.statements as Array<Record<string, unknown>>
    )[0];
    if (!signedStatement) throw new Error('Signed VEX statement is missing');
    signedStatement.impact_statement = 'Attacker replaced this content.';
    expect(() =>
      parseVexDocument(signed, 'openvex', {
        trustedPublicKeyPem: keys.publicKey
          .export({ type: 'spki', format: 'pem' })
          .toString(),
        trustedKeyId: 'security-team-2026'
      })
    ).toThrow('signature verification failed');
  });

  it('signs CycloneDX documents inside metadata properties and verifies canonical fields', () => {
    const document = exportCycloneDxVex([vulnerabilityFinding()], {
      author: 'Trusted assessor',
      timestamp: '2026-11-06T10:00:00.000Z'
    });
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const signed = signVexDocument(
      document,
      'cyclonedx',
      keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      'security-team-2026'
    );
    expect(
      parseVexDocument(signed, 'cyclonedx', {
        trustedPublicKeyPem: publicKey,
        trustedKeyId: 'security-team-2026'
      })[0]?.signatureStatus
    ).toBe('verified');
    const signedVulnerability = (
      signed.vulnerabilities as Array<Record<string, unknown>>
    )[0];
    if (!signedVulnerability)
      throw new Error('CycloneDX vulnerability is missing');
    signedVulnerability.recommendation = 'Attacker changed the recommendation.';
    expect(() =>
      parseVexDocument(signed, 'cyclonedx', {
        trustedPublicKeyPem: publicKey,
        trustedKeyId: 'security-team-2026'
      })
    ).toThrow('signature verification failed');
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
