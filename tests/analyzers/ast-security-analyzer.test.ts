import { describe, expect, it } from 'vitest';
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

    expect(
      findings.map((finding) => finding.ruleId)
    ).toEqual([
      'TLP-AST-001',
      'TLP-AST-002'
    ]);
  });
});
