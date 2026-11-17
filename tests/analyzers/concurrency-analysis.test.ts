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

  it('flags realpath validation followed by reopening the same path', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      `import { realpath, readFile } from 'node:fs/promises';
async function load(path: string) {
  await realpath(path);
  return readFile(path);
}`
    );

    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-RACE-001');
  });

  it('tracks a realpath result back to the path later reopened', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      `import { realpath, readFile } from 'node:fs/promises';
async function load(path: string) {
  const canonicalPath = await realpath(path);
  return readFile(canonicalPath);
}`
    );

    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-RACE-001');
  });

  it('follows immutable local path aliases in filesystem check-then-use flows', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      `import { access, readFile } from 'node:fs/promises';
       async function load(path: string) {
         await access(path);
         const reopenedPath = path;
         return readFile(reopenedPath);
       }`
    );
    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-RACE-001');
  });

  it('does not resolve a path alias before its declaration', () => {
    const findings = analyzeAstSource(
      'src/storage.ts',
      `import { access, readFile } from 'node:fs/promises';
       async function load(path: string) {
         const content = await readFile(reopenedPath);
         const reopenedPath = path;
         await access(path);
         return content;
       }`
    );
    expect(findings.map((finding) => finding.ruleId)).not.toContain(
      'TLP-RACE-001'
    );
  });

  it('checks destination paths for filesystem moves and copies', () => {
    for (const operation of [
      'rename(source, destination)',
      'copyFile(source, destination)'
    ]) {
      const findings = analyzeAstSource(
        'src/storage.ts',
        `import { access, copyFile, rename } from 'node:fs/promises';
         async function move(source: string, destination: string) {
           await access(destination);
           await ${operation};
         }`
      );
      expect(findings.map((finding) => finding.ruleId)).toContain(
        'TLP-RACE-001'
      );
    }
  });

  it('flags checked paths reopened through file handles and streams', () => {
    for (const operation of ["open(path, 'r')", 'createWriteStream(path)']) {
      const findings = analyzeAstSource(
        'src/storage.ts',
        `import { access, open } from 'node:fs/promises';
         import { createWriteStream } from 'node:fs';
         async function load(path: string) {
           await access(path);
           await ${operation};
         }`
      );
      expect(findings.map((finding) => finding.ruleId)).toContain(
        'TLP-RACE-001'
      );
    }
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
    const sequelizeSerializable = analyzeAstSource(
      'src/purchase.ts',
      `async function purchase(id: string) {
  await sequelize.transaction({ isolationLevel: Transaction.ISOLATION_LEVELS.SERIALIZABLE }, async (tx) => {
    const item = await tx.item.findUnique({ where: { id } });
    if (item.stock > 0) {
      await tx.item.update({ where: { id }, data: { stock: item.stock - 1 } });
    }
  });
}`
    );

    expect(
      missingPredicate.some((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toBe(true);
    expect(
      serializable.some((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toBe(false);
    expect(
      sequelizeSerializable.some((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toBe(false);
  });

  it('flags non-atomic Redis check-then-set but accepts SET NX', () => {
    const unsafe = analyzeAstSource(
      'src/locks.ts',
      `async function reserve(key: string, payload: string) {
  const existing = await redis.exists(key);
  if (!existing) await redis.set(key, payload);
}`
    );
    const atomic = analyzeAstSource(
      'src/locks.ts',
      `async function reserve(key: string, payload: string) {
  const existing = await redis.exists(key);
  if (!existing) await redis.set(key, payload, { NX: true, PX: 5000 });
}`
    );
    const atomicTemplate = analyzeAstSource(
      'src/locks.ts',
      `async function reserve(key: string, payload: string) {
  const existing = await redis.exists(key);
  if (!existing) await redis.set(key, payload, \`NX\`);
}`
    );

    expect(unsafe.map((finding) => finding.ruleId)).toContain('TLP-RACE-002');
    expect(atomic.map((finding) => finding.ruleId)).not.toContain(
      'TLP-RACE-002'
    );
    expect(atomicTemplate.map((finding) => finding.ruleId)).not.toContain(
      'TLP-RACE-002'
    );
    expect(JSON.stringify(unsafe)).not.toContain('payload');
  });

  it('follows a unique const Redis client alias and rejects a mutable client alias', () => {
    const immutable = analyzeAstSource(
      'src/locks.ts',
      `async function reserve(key: string, payload: string) {
  const cache = redis;
  const existing = await cache.get(key);
  if (!existing) await cache.set(key, payload);
}`
    );
    const mutable = analyzeAstSource(
      'src/locks.ts',
      `async function reserve(key: string, payload: string) {
  let cache = redis;
  const existing = await cache.get(key);
  if (!existing) await cache.set(key, payload);
}`
    );

    expect(immutable.map((finding) => finding.ruleId)).toContain(
      'TLP-RACE-002'
    );
    expect(mutable.map((finding) => finding.ruleId)).not.toContain(
      'TLP-RACE-002'
    );
  });

  it('handles many Redis check-then-set keys with bounded source passes', () => {
    const lines = Array.from({ length: 256 }, (_, index) => [
      `const present${index} = await redis.exists(key${index});`,
      `if (!present${index}) await redis.set(key${index}, value${index});`
    ]).flat();
    const findings = analyzeAstSource(
      'src/many-locks.ts',
      `async function reserveMany() {\n${lines.join('\n')}\n}`
    ).filter((finding) => finding.ruleId === 'TLP-RACE-002');

    expect(findings).toHaveLength(256);
    expect(JSON.stringify(findings)).not.toContain('key0');
    expect(JSON.stringify(findings)).not.toContain('value0');
  });

  it('flags discarded database transaction promises but accepts awaited or returned transactions', () => {
    const findings = analyzeAstSource(
      'src/transactions.ts',
      `async function discarded() {
  db.$transaction(async (tx) => tx.invoice.update({ where: { id: '1' }, data: { paid: true } }));
  void prisma.$transaction(async (tx) => tx.invoice.update({ where: { id: '2' }, data: { paid: true } }));
  db.$transaction(async (tx) => tx.invoice.update({ where: { id: '5' }, data: { paid: true } })).then(() => notify());
}
async function observed() {
  await db.$transaction(async (tx) => tx.invoice.update({ where: { id: '3' }, data: { paid: true } }));
  return prisma.$transaction(async (tx) => tx.invoice.update({ where: { id: '4' }, data: { paid: true } }));
}
function customClient() {
  utility.transaction(() => persist());
}`
    );
    const transactions = findings.filter(
      (finding) => finding.ruleId === 'TLP-RACE-004'
    );
    expect(transactions).toHaveLength(3);
    expect(transactions.map((finding) => finding.location?.line)).toEqual([
      2, 3, 4
    ]);
    expect(
      transactions.every((finding) => finding.metadata?.cwe === 'CWE-362')
    ).toBe(true);
  });

  it('follows immutable database receiver aliases but rejects mutable aliases', () => {
    const findings = analyzeAstSource(
      'src/transactions.ts',
      `function immutableAlias() {
  const dbAlias = db;
  const transactionClient = dbAlias;
  transactionClient.$transaction(() => writeInvoice());
}
function mutableAlias() {
  let dbAlias = db;
  dbAlias = utility;
  dbAlias.transaction(() => writeOther());
}`
    ).filter((finding) => finding.ruleId === 'TLP-RACE-004');

    expect(findings.map((finding) => finding.location?.line)).toEqual([4]);
  });

  it('recognizes statically computed transaction method names', () => {
    const findings = analyzeAstSource(
      'src/transactions.ts',
      `function persist() {
  db['$transaction'](() => writeInvoice());
  database['transaction'](() => writePayment()).catch(reportError);
  const method = getMethod();
  db[method](() => writeOther());
}`
    ).filter((finding) => finding.ruleId === 'TLP-RACE-004');

    expect(findings.map((finding) => finding.location?.line)).toEqual([2, 3]);
  });

  it('does not trust a custom transaction method as a serializable database lock', () => {
    const findings = analyzeAstSource(
      'src/purchase.ts',
      `async function purchase(id: string) {
  await utility.transaction(async () => {
    const item = await db.item.findUnique({ where: { id } });
    if (item.stock > 0) {
      await db.item.update({ where: { id }, data: { stock: item.stock - 1 } });
    }
  }, { isolationLevel: 'Serializable' });
}`
    );
    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toHaveLength(1);
  });

  it('does not trust a serializable callback whose database operations bypass its transaction client', () => {
    const findings = analyzeAstSource(
      'src/purchase.ts',
      `async function purchase(id: string) {
  await db.$transaction(async (tx) => {
    const item = await db.item.findUnique({ where: { id } });
    if (item.stock > 0) {
      await db.item.update({ where: { id }, data: { stock: item.stock - 1 } });
    }
  }, { isolationLevel: 'Serializable' });
}`
    );
    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toHaveLength(1);
  });

  it('does not mistake a nested unrelated CAS call for an atomic database update', () => {
    const findings = analyzeAstSource(
      'src/spend.ts',
      `async function spend(id: string) {
        const account = await db.account.findUnique({ where: { id } });
        if (account.balance > 0) {
          await db.account.update({
            where: { id },
            data: { balance: account.balance - compareAndSwap(otherCounter, id) }
          });
        }
      }`
    );
    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-002')
    ).toHaveLength(1);
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

  it('traces same-function immutable aliases of an unbounded side-effecting map', () => {
    const unbounded = analyzeAstSource(
      'src/batch-alias.ts',
      `async function updateAll(ids: string[]) {
  const jobs = ids.map(async (id) => db.item.update({ where: { id }, data: { active: true } }));
  await Promise.all(jobs);
}`
    );
    expect(
      unbounded.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(1);

    const bounded = analyzeAstSource(
      'src/batch-alias.ts',
      `async function updateAll(ids: string[]) {
  const jobs = ids.slice(0, 8).map(async (id) => db.item.update({ where: { id }, data: { active: true } }));
  await Promise.all(jobs);
}`
    );
    expect(
      bounded.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(0);

    const dynamic = analyzeAstSource(
      'src/batch-alias.ts',
      `async function updateAll(ids: string[]) {
  let jobs = ids.map(async (id) => db.item.update({ where: { id }, data: { active: true } }));
  jobs = [];
  await Promise.all(jobs);
}`
    );
    expect(
      dynamic.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toHaveLength(0);
  });

  it('flags side-effect fan-out through allSettled, race and any combinators', () => {
    for (const combinator of ['allSettled', 'race', 'any']) {
      const findings = analyzeAstSource(
        'src/batch-update.ts',
        `async function updateAll(ids: string[]) {
  await Promise.${combinator}(ids.map(async (id) => db.item.update({ where: { id }, data: { active: true } })));
}`
      );

      expect(
        findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
      ).toHaveLength(1);
    }
  });

  it('accepts a statically bounded allSettled side-effect batch', () => {
    const findings = analyzeAstSource(
      'src/batch-update.ts',
      `async function updateAll(ids: string[]) {
  await Promise.allSettled(ids.slice(0, 4).map(async (id) => db.item.update({ where: { id }, data: { active: true } })));
}`
    );

    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-RACE-003')
    ).toEqual([]);
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
