import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import AjvDraft04 from 'ajv-draft-04';
import addFormats from 'ajv-formats';
import { createSarifReport } from '../../src/core/sarif.js';
import { writeSarifReport } from '../../src/core/report-writer.js';

const sarifSchema = JSON.parse(
  await readFile(
    new URL('../fixtures/sarif-schema-2.1.0.json', import.meta.url),
    'utf8'
  )
) as object;

describe('SARIF serialization', () => {
  it('emits stable fingerprints and unsuccessful invocation on partial coverage', () => {
    const finding = {
      id: 'r-1',
      ruleId: 'TOOLIP001',
      title: 'unsafe',
      category: 'injection',
      severity: 'high' as const,
      confidence: 'high' as const,
      message: 'finding',
      source: 'test',
      location: { file: 'src/a.ts', line: 2 }
    };
    const first = createSarifReport({
      findings: [finding],
      analysisState: 'partial',
      toolVersion: '2.2.1',
      policy: {
        decision: 'incomplete',
        policySha256: 'a'.repeat(64),
        reasons: ['scan is partial']
      }
    }) as {
      runs: Array<{
        results: Array<{ partialFingerprints: Record<string, string> }>;
        invocations: Array<{
          executionSuccessful: boolean;
          properties: Record<string, unknown>;
        }>;
      }>;
    };
    const moved = createSarifReport({
      findings: [{ ...finding, location: { file: 'src/a.ts', line: 20 } }],
      analysisState: 'complete',
      toolVersion: '2.2.1'
    }) as typeof first;
    expect(first.runs[0]?.invocations[0]?.executionSuccessful).toBe(false);
    expect(first.runs[0]?.invocations[0]?.properties).toMatchObject({
      policyDecision: 'incomplete',
      policySha256: 'a'.repeat(64),
      policyReasons: ['scan is partial']
    });
    expect(first.runs[0]?.results[0]?.partialFingerprints).toEqual(
      moved.runs[0]?.results[0]?.partialFingerprints
    );
  });

  it('writes the integrated sanitized report artifact', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-sarif-'));
    try {
      const output = path.join(root, 'results.sarif');
      await writeSarifReport(output, {
        findings: [],
        analysisState: 'partial',
        toolVersion: '3.2.1-rc'
      });
      const parsed = JSON.parse(await readFile(output, 'utf8')) as {
        version: string;
        runs: Array<{ invocations: Array<{ executionSuccessful: boolean }> }>;
      };
      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs[0]?.invocations[0]?.executionSuccessful).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps duplicate occurrence fingerprints distinct and stable across line moves', () => {
    const first = {
      id: 'secret-1',
      ruleId: 'TOOLIP-SECRET-GITHUB-TOKEN',
      title: 'GitHub token detected',
      category: 'secrets',
      severity: 'critical' as const,
      confidence: 'high' as const,
      message: 'A GitHub token-like secret was found.',
      source: 'test',
      location: { file: 'src/app.ts', line: 12, column: 4 },
      evidence: [{ summary: '[redacted secret]', fingerprint: 'a'.repeat(64) }]
    };
    const second = {
      ...first,
      id: 'secret-2',
      location: { file: 'src/app.ts', line: 13, column: 4 }
    };
    const reportFingerprints = (
      findings: readonly (typeof first | typeof second)[]
    ) =>
      (
        createSarifReport({
          findings,
          analysisState: 'complete',
          toolVersion: '3.2.1-rc'
        }).runs as Array<{
          results: Array<{ partialFingerprints: Record<string, string> }>;
        }>
      )[0]?.results.map((result) => result.partialFingerprints['toolip/v1']);

    const original = reportFingerprints([first, second]);
    const moved = reportFingerprints([
      { ...first, location: { ...first.location, line: 100 } },
      { ...second, location: { ...second.location, line: 101 } }
    ]);
    expect(original?.[0]).not.toBe(original?.[1]);
    expect(moved).toEqual(original);
  });

  it('validates complete and incomplete reports against the official SARIF 2.1.0 schema', () => {
    const ajv = new AjvDraft04({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(sarifSchema);
    const finding = {
      id: 'stable-finding',
      ruleId: 'TLP-TEST-001',
      title: 'Unsafe sample call',
      category: 'injection',
      severity: 'high' as const,
      confidence: 'high' as const,
      message: 'Untrusted input reaches a command sink.',
      source: 'test',
      location: { file: 'src/app.ts', line: 12, column: 3 }
    };
    const complete = createSarifReport({
      findings: [finding],
      analysisState: 'complete',
      toolVersion: '3.2.1-rc'
    });
    const partial = createSarifReport({
      findings: [],
      analysisState: 'partial',
      toolVersion: '3.2.1-rc',
      policy: {
        decision: 'incomplete',
        policySha256: 'a'.repeat(64),
        reasons: ['source coverage incomplete']
      }
    });
    expect(
      (
        complete.runs as Array<{
          results: Array<{ partialFingerprints: Record<string, string> }>;
        }>
      )[0]?.results[0]?.partialFingerprints['toolip/v1']
    ).toMatch(/^[a-f0-9]{64}$/u);
    for (const report of [complete, partial])
      expect(validate(report), JSON.stringify(validate.errors)).toBe(true);
  });

  it('encodes repository paths and fails closed on unsafe SARIF identities', () => {
    const ajv = new AjvDraft04({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(sarifSchema);
    const finding = {
      id: 'stable-finding',
      ruleId: 'TLP-TEST-001',
      title: 'Unsafe sample call',
      category: 'injection',
      severity: 'high' as const,
      confidence: 'high' as const,
      message: 'Untrusted input reaches a command sink.',
      source: 'test',
      location: { file: 'src/a file.ts', line: 12 }
    };
    const syntheticCredential = ['ghp_', '123456789012345678901234567890'].join(
      ''
    );
    const report = createSarifReport({
      findings: [
        finding,
        {
          ...finding,
          id: 'unsafe-finding',
          ruleId: '../unsafe-rule',
          location: { file: '../../outside.ts', line: 1 }
        },
        {
          ...finding,
          id: 'credential-path',
          location: { file: `src/${syntheticCredential}.ts`, line: 2 }
        },
        {
          ...finding,
          id: 'unicode-path',
          location: { file: `src/${String.fromCharCode(0xd800)}.ts`, line: 3 }
        }
      ],
      analysisState: 'complete',
      toolVersion: '3.2.1-rc'
    }) as {
      runs: Array<{
        results: Array<{
          ruleId: string;
          locations?: Array<{
            physicalLocation: { artifactLocation: { uri: string } };
          }>;
          properties: Record<string, unknown>;
        }>;
        invocations: Array<{
          executionSuccessful: boolean;
          properties: Record<string, unknown>;
        }>;
      }>;
    };
    const run = report.runs[0];
    expect(
      run?.results[0]?.locations?.[0]?.physicalLocation.artifactLocation.uri
    ).toBe('src/a%20file.ts');
    expect(run?.results[1]).toMatchObject({
      ruleId: 'TOOLIP-INVALID-RULE-ID',
      properties: { locationOmitted: true }
    });
    expect(run?.results[1]?.locations).toBeUndefined();
    expect(run?.results[2]?.locations).toBeUndefined();
    expect(run?.results[3]?.locations).toBeUndefined();
    expect(run?.invocations[0]).toMatchObject({
      executionSuccessful: false,
      properties: {
        analysisState: 'failed',
        invalidRuleIdCount: 1,
        invalidArtifactLocationCount: 3
      }
    });
    expect(JSON.stringify(report)).not.toContain(syntheticCredential);
    expect(validate(report), JSON.stringify(validate.errors)).toBe(true);
  });
});
