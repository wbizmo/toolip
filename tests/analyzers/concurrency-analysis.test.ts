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
    expect(
      findings.filter((finding) => finding.ruleId.startsWith('TLP-RACE-'))
    ).toEqual([]);
  });

  it('requires the read version in the update predicate and recognizes serializable transactions', () => {
    const missingPredicate = analyzeAstSource(
      'src/purchase.ts',
      `async function purchase(id: string) {
  const item = await db.item.findUnique({ where: { id } });
  if (item.stock > 0) {
    await db.item.update({ where: { id }, data: { stock: item.stock - 1, version: item.version + 1 } });
  }
}`
    );
    const serializable = analyzeAstSource(
      'src/purchase.ts',
      `async function purchase(id: string) {
  await db.$transaction(async (tx) => {
    const item = await tx.item.findUnique({ where: { id } });
    if (item.stock > 0) {
      await tx.item.update({ where: { id }, data: { stock: item.stock - 1 } });
    }
  }, { isolationLevel: 'Serializable' });
}`
    );

    expect(
      missingPredicate.some((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toBe(true);
    expect(
      serializable.some((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toBe(false);
  });

  it('does not treat safe independent Promise.all work as a race', () => {
    const findings = analyzeAstSource(
      'src/batch.ts',
      `async function load(ids: string[]) {
         return Promise.all(ids.map((id) => db.item.findUnique({ where: { id } })));
       }`
    );
    expect(
      findings.filter((finding) => finding.ruleId.startsWith('TLP-RACE-'))
    ).toEqual([]);
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

  it('follows bounded same-file async wrappers in unbounded Promise.all work', () => {
    const findings = analyzeAstSource(
      'src/batch-update.ts',
      `async function persistItem(id: string) {
  await repository.update({ where: { id }, data: { active: true } });
}
async function updateAll(ids: string[]) {
  await Promise.all(ids.map(async (id) => persistItem(id)));
}`
    );
    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(1);
    expect(findings[0]?.metadata).toMatchObject({
      cwe: 'CWE-400',
      limitation: expect.stringContaining('Static same-function heuristic')
    });
  });

  it('keeps unresolved external Promise.all callbacks as low-confidence candidates', () => {
    const findings = analyzeAstSource(
      'src/batch-update.ts',
      `async function updateAll(ids: string[]) {
  await Promise.all(ids.map(persistItem));
}`
    );

    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(1);
    expect(
      findings.find((finding) => finding.ruleId === 'TLP-RACE-003')?.confidence
    ).toBe('low');
  });

  it('does not trust a generic local limiter name to bound fan-out', () => {
    const findings = analyzeAstSource(
      'src/batch-update.ts',
      `async function updateAll(ids: string[], limit: (callback: () => Promise<unknown>) => unknown) {
  await Promise.all(ids.map((id) => limit(() => db.item.update({ where: { id }, data: { active: true } }))));
}`
    );

    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(1);
  });

  it('accepts a statically bounded imported p-limit pool', () => {
    const findings = analyzeAstSource(
      'src/batch-update.ts',
      `import pLimit from 'p-limit';
const limit = pLimit(4);
async function updateAll(ids: string[]) {
  await Promise.all(ids.map((id) => limit(() => db.item.update({ where: { id }, data: { active: true } }))));
}`
    );

    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toEqual([]);
  });

  it('does not trust a shadowed p-limit factory import', () => {
    const findings = analyzeAstSource(
      'src/batch-update.ts',
      `import pLimit from 'p-limit';
async function updateAll(ids: string[]) {
  function pLimit(_concurrency: number) { return (callback: () => Promise<unknown>) => callback(); }
  const limit = pLimit(4);
  await Promise.all(ids.map((id) => limit(() => db.item.update({ where: { id }, data: { active: true } }))));
}`
    );

    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(1);
  });

  it.each([
    ['above the recognized cap', 'pLimit(33)'],
    ['dynamic', 'pLimit(getConcurrency())'],
    ['mutated after construction', 'pLimit(4);\nlimit.concurrency = 100']
  ])(
    'does not accept an unbounded p-limit pool that is %s',
    (_label, setup) => {
      const declaration = setup.startsWith('pLimit')
        ? `const limit = ${setup};`
        : `const limit = ${setup};`;
      const findings = analyzeAstSource(
        'src/batch-update.ts',
        `import pLimit from 'p-limit';
${declaration}
async function updateAll(ids: string[]) {
  await Promise.all(ids.map((id) => limit(() => db.item.update({ where: { id }, data: { active: true } }))));
}`
      );

      expect(
        findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
      ).toHaveLength(1);
    }
  );
});
