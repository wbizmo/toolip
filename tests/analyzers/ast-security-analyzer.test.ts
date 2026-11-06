import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { AstSecurityAnalyzer } from '../../src/analyzers/ast/ast-security-analyzer.js';
import { analyzeAstSource } from '../../src/analyzers/ast/source-analysis.js';

describe('AST security source analysis', () => {
  it('does not confuse RegExp.exec() with child_process.exec()', () => {
    const findings = analyzeAstSource(
      'auth.service.ts',
      `
export function parseDuration(value: string) {
  return /^(\\d+)([smhd])$/.exec(value);
}
`
    );

    expect(findings).toEqual([]);
  });

  it('detects named child_process exec imports', () => {
    const findings = analyzeAstSource(
      'runner.ts',
      `
import { exec } from 'node:child_process';

exec(userInput);
`
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('TLP-AST-003');
  });

  it('detects aliased child_process exec imports', () => {
    const findings = analyzeAstSource(
      'runner.ts',
      `
import { exec as runShell } from 'child_process';

runShell(userInput);
`
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('TLP-AST-003');
  });

  it('detects namespace execSync calls', () => {
    const findings = analyzeAstSource(
      'runner.ts',
      `
import * as childProcess from 'node:child_process';

childProcess.execSync(userInput);
`
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('TLP-AST-004');
  });

  it('detects CommonJS destructured exec calls', () => {
    const findings = analyzeAstSource(
      'runner.cjs',
      `
const { exec: runShell } = require('node:child_process');

runShell(userInput);
`
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('TLP-AST-003');
  });

  it('detects eval and Function constructor usage', () => {
    const findings = analyzeAstSource(
      'dynamic.ts',
      `
eval(source);
const generated = new Function('value', source);
`
    );

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-AST-001',
      'TLP-AST-002'
    ]);
  });

  it('does not retain literal arguments in AST evidence', () => {
    const token = `ghp_${'a'.repeat(36)}`;
    const findings = analyzeAstSource('runner.ts', `eval("${token}");`);
    expect(findings).toHaveLength(1);
    expect(JSON.stringify(findings)).not.toContain(token);
    expect(findings[0]?.evidence?.[0]?.summary).toMatch(
      /^\[source expression redacted;/
    );
  });

  it('binds AST findings to the verified source snapshot', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-ast-provenance-')
    );
    const content = 'eval(input);';

    try {
      await writeFile(path.join(root, 'app.ts'), content);
      const result = await new AstSecurityAnalyzer().analyze({ root });
      const finding = result.findings[0];

      expect(finding?.metadata?.sourceProvenance).toMatchObject({
        path: 'app.ts',
        sha256: createHash('sha256').update(content).digest('hex'),
        bytes: Buffer.byteLength(content),
        discoverySnapshot: { size: Buffer.byteLength(content) },
        readSnapshot: { size: Buffer.byteLength(content) }
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
