import { describe, expect, it } from 'vitest';
import { analyzeAstSource } from '../../src/analyzers/ast/source-analysis.js';

describe('AST concurrency candidates', () => {
  it('flags same-path filesystem check then use', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      `import { access, readFile } from 'node:fs/promises';
       async function load(path: string) {
         await access(path);
         return readFile(path);
       }`
    );
    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-RACE-001');
  });

  it('flags database read-check-write candidates without atomic predicates', () => {
    const findings = analyzeAstSource(
      'src/purchase.ts',
      `async function purchase(id: string) {
         const item = await db.item.findUnique({ where: { id } });
         if (item.stock > 0) {
           await db.item.update({ where: { id }, data: { stock: item.stock - 1 } });
         }
       }`
    );
    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-RACE-002');
  });

  it('does not flag visible versioned updates or operations through one opened handle', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      `async function update(path: string, id: string) {
         const handle = await open(path, 'r');
         await handle.readFile();
         const item = await db.item.findUnique({ where: { id } });
         if (item.stock > 0) {
           await db.item.update({
             where: { id, version: item.version },
             data: { stock: item.stock - 1, version: item.version + 1 }
           });
         }
       }`
    );
    expect(findings.filter((finding) => finding.ruleId.startsWith('TLP-RACE-'))).toEqual(
      []
    );
  });

  it('does not treat safe independent Promise.all work as a race', () => {
    const findings = analyzeAstSource(
      'src/batch.ts',
      `async function load(ids: string[]) {
         return Promise.all(ids.map((id) => db.item.findUnique({ where: { id } })));
       }`
    );
    expect(findings.filter((finding) => finding.ruleId.startsWith('TLP-RACE-'))).toEqual(
      []
    );
  });

  it('flags unbounded side-effecting Promise.all work but accepts a static cap', () => {
    const findings = analyzeAstSource(
      'src/batch-update.ts',
      `async function updateAll(ids: string[]) {
         await Promise.all(ids.map(async (id) => db.item.update({ where: { id }, data: { active: true } })));
         await Promise.all(ids.slice(0, 8).map(async (id) => db.item.update({ where: { id }, data: { archived: true } })));
       }`
    );
    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(1);
    expect(
      findings.find((finding) => finding.ruleId === 'TLP-RACE-003')?.confidence
    ).toBe('low');
  });
});
