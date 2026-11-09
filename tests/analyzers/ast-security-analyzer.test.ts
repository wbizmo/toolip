import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { AstSecurityAnalyzer } from '../../src/analyzers/ast/ast-security-analyzer.js';
import {
  analyzeAstSource,
  createAstProjectAnalysis,
  type AstProjectInput
} from '../../src/analyzers/ast/source-analysis.js';

function requiredProjectInput(
  inputs: readonly AstProjectInput[],
  index: number
): AstProjectInput {
  const input = inputs[index];
  if (!input) throw new Error(`missing AST project input at index ${index}`);
  return input;
}

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

  it('detects the default ESM child_process namespace import', () => {
    const findings = analyzeAstSource(
      'runner.mjs',
      `import childProcess from 'node:child_process';\nchildProcess.exec(userInput);`
    );

    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-AST-003');
  });

  it('ignores lexically shadowed child_process names and resolves local aliases', () => {
    const findings = analyzeAstSource(
      'runner.ts',
      `import { exec } from 'node:child_process';
import * as childProcess from 'child_process';
function harmless(exec: (value: string) => void, childProcess: { exec: (value: string) => void }) {
  exec('safe');
  childProcess.exec('safe');
}
{
  const childProcess = { exec: (value: string) => value };
  childProcess.exec('safe');
}
const execute = exec;
const cp = childProcess;
execute(untrusted);
cp.execSync(untrusted);
`
    );

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-AST-003',
      'TLP-AST-004'
    ]);
  });

  it('recognizes CommonJS property aliases and ignores a shadowed require', () => {
    const findings = analyzeAstSource(
      'runner.cjs',
      `const { exec: run } = require('node:child_process');
run(input);
function safe(require) {
  const cp = require('child_process');
  cp.exec('safe');
}
`
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('TLP-AST-003');
  });

  it('flags request data passed to the imported node-serialize deserializer', () => {
    const namedImport = analyzeAstSource(
      'deserialize.ts',
      `import { unserialize as decode } from 'node-serialize';
export function handle(req: { body: { payload: string } }) {
  return decode(req.body.payload);
}`
    );
    const commonJsAlias = analyzeAstSource(
      'deserialize.cjs',
      `const decode = require('node-serialize').unserialize;
function handle(req) { return decode(req.query.payload); }`
    );

    expect(
      [...namedImport, ...commonJsAlias]
        .filter((finding) => finding.ruleId === 'TLP-AST-012')
        .map((finding) => finding.location?.file)
    ).toEqual(['deserialize.ts', 'deserialize.cjs']);
  });

  it('does not treat JSON.parse or a lexically shadowed unserialize name as unsafe', () => {
    const findings = analyzeAstSource(
      'deserialize.ts',
      `import { unserialize } from 'node-serialize';
export function parse(req: { body: { payload: string } }) {
  JSON.parse(req.body.payload);
  function safe(unserialize: (input: string) => unknown) {
    return unserialize(req.body.payload);
  }
}`
    );

    expect(findings.some((finding) => finding.ruleId === 'TLP-AST-012')).toBe(
      false
    );
  });

  it('propagates child_process aliases through a reverse-ordered binding chain', () => {
    const findings = analyzeAstSource(
      'runner.cjs',
      `var first = second;
var second = third;
var third = childProcess;
var childProcess = require('node:child_process');
first.exec(input);`
    );

    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-AST-003');
  });

  it('does not retain dangerous API identity after an alias is reassigned', () => {
    const findings = analyzeAstSource(
      'runner.ts',
      `import { exec } from 'node:child_process';
let run = exec;
run = (value: string) => value;
run(untrusted);`
    );

    expect(findings.some((finding) => finding.ruleId === 'TLP-AST-003')).toBe(
      false
    );
  });

  it('keeps detection before a later straight-line alias reassignment', () => {
    const findings = analyzeAstSource(
      'runner.ts',
      `import { exec } from 'node:child_process';
let run = exec;
run(untrusted);
run = (value: string) => value;`
    );

    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-AST-003');
  });

  it('keeps a low-confidence candidate when reassignment is conditional', () => {
    const findings = analyzeAstSource(
      'runner.ts',
      `import { exec } from 'node:child_process';
let run = (value: string) => value;
if (condition) run = exec;
run(untrusted);`
    );

    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-AST-011');
  });

  it('bounds long reassignment chains and reports their unresolved call', () => {
    const writes = Array.from({ length: 300 }, () => 'run = run;').join('\n');
    const findings = analyzeAstSource(
      'runner.ts',
      `import { exec } from 'node:child_process';
let run = exec;
${writes}
run(untrusted);`
    );

    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-AST-011');
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

  it('tracks request input into targeted injection sinks', () => {
    const findings = analyzeAstSource(
      'routes.ts',
      `
async function handler(req: RequestLike, db: Database) {
  const userId = req.query.id;
  await db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
  await fetch(req.query.destination);
  element.innerHTML = req.body.html;
  Object.assign({}, req.body);
}
`
    );

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-AST-005',
      'TLP-AST-006',
      'TLP-AST-007',
      'TLP-AST-008'
    ]);
    expect(findings.every((finding) => finding.confidence === 'medium')).toBe(
      true
    );
  });

  it('preserves taint through computed request fields and Promise callbacks', () => {
    const findings = analyzeAstSource(
      'routes.ts',
      `function handler(req: RequestLike, db: Database) {
  db.query(req.body[req.query.field]);
  Promise.resolve(req.query.sql).then((sql) => db.query(sql));
}`
    );
    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-AST-005')
    ).toHaveLength(2);
  });

  it('accepts only an HTML-context encoder at HTML sinks and not other sinks', () => {
    const findings = analyzeAstSource(
      'routes.ts',
      `function handler(req: RequestLike, db: Database) {
  element.innerHTML = escapeHtml(req.body.html);
  element.innerHTML = genericSanitize(req.body.otherHtml);
  db.query(escapeHtml(req.query.sql));
}`
    );
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-AST-007',
      'TLP-AST-005'
    ]);
  });

  it('accepts a fail-closed literal fetch host allowlist and rejects dynamic policies or redirects', () => {
    const findings = analyzeAstSource(
      'routes.ts',
      `async function handler(req: RequestLike) {
  const url = new URL(req.query.destination);
  if (!['service.example'].includes(url.hostname)) throw new Error('blocked');
  await fetch(url, { redirect: 'error' });
  const other = new URL(req.query.other);
  if (!getAllowedHosts().includes(other.hostname)) throw new Error('blocked');
  await fetch(other, { redirect: 'error' });
  const local = new URL(req.query.local);
  if (!['localhost'].includes(local.hostname)) throw new Error('blocked');
  await fetch(local, { redirect: 'error' });
  const changed = new URL(req.query.changed);
  if (!['service.example'].includes(changed.hostname)) throw new Error('blocked');
  changed.hostname = '127.0.0.1';
  await fetch(changed, { redirect: 'error' });
  await fetch(url);
}`
    );
    expect(
      findings.filter((finding) => finding.ruleId === 'TLP-AST-006')
    ).toHaveLength(4);
  });

  it('distinguishes tainted shell commands from safe argument-array execution', () => {
    const findings = analyzeAstSource(
      'commands.ts',
      `import { exec as run, execFile, spawn } from 'node:child_process';
function handler(req: RequestLike) {
  run(req.query.command);
  execFile('git', ['show', req.query.revision]);
  spawn('git', ['show', req.query.revision]);
  execFile('tool', [req.query.command], { shell: true });
}`
    );
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-AST-003',
      'TLP-AST-010',
      'TLP-AST-010'
    ]);
  });

  it('treats unresolved computed child-process methods as uncertain execution', () => {
    const findings = analyzeAstSource(
      'commands.ts',
      `import * as childProcess from 'node:child_process';
function handler(req: RequestLike) {
  childProcess[req.query.method](req.query.argument);
  childProcess['exec'](req.query.command);
}`
    );
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-AST-011',
      'TLP-AST-003',
      'TLP-AST-010'
    ]);
    expect(findings[0]?.confidence).toBe('low');
  });

  it('tracks request-derived paths into verified filesystem APIs but respects shadowing', () => {
    const findings = analyzeAstSource(
      'files.ts',
      `import * as fs from 'node:fs/promises';
import { readFile as load } from 'fs/promises';
import path from 'node:path';
async function handler(req: RequestLike) {
  const candidate = path.resolve('/srv/data', req.query.file);
  await fs.readFile(candidate);
  await load(req.params.name);
}
function harmless(readFile: (path: string) => void, req: RequestLike) {
  readFile(req.query.name);
}`
    );
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-AST-009',
      'TLP-AST-009'
    ]);
    expect(findings.every((finding) => finding.confidence === 'medium')).toBe(
      true
    );
  });

  it('propagates request taint through local helper parameters and return values', () => {
    const findings = analyzeAstSource(
      'routes.ts',
      `function executeQuery(db: Database, sql: string) {
  db.query(sql);
}
function identity(value: string) {
  return value;
}
function handler(req: RequestLike, db: Database) {
  executeQuery(db, identity(req.query.statement));
}`
    );

    expect(findings.map((finding) => finding.ruleId)).toEqual(['TLP-AST-005']);
    expect(findings[0]?.evidence?.[0]?.summary).toMatch(
      /^\[source expression redacted/u
    );
  });

  it('resolves imported and re-exported helper calls from the immutable project graph', () => {
    const root = path.join(os.tmpdir(), 'toolip-ast-symbols');
    const routePath = path.join(root, 'routes.ts');
    const queryPath = path.join(root, 'queries.ts');
    const databasePath = path.join(root, 'database.ts');
    const route = `import { execute } from './queries.js';
export function handler(req: RequestLike, db: Database) {
  execute(db, req.query.statement);
}`;
    const query = `export { runQuery as execute } from './database.js';`;
    const database = `export function runQuery(db: Database, sql: string) {
  db.query(sql);
}`;
    const project = createAstProjectAnalysis([
      { filePath: 'routes.ts', absolutePath: routePath, content: route },
      { filePath: 'queries.ts', absolutePath: queryPath, content: query },
      { filePath: 'database.ts', absolutePath: databasePath, content: database }
    ]);

    const findings = analyzeAstSource('database.ts', database, project);
    expect(findings.map((finding) => finding.ruleId)).toEqual(['TLP-AST-005']);
    expect(findings[0]?.location?.file).toBe('database.ts');
  });

  it('follows cross-file async wrappers and Promise callbacks to a SQL sink', () => {
    const root = path.join(os.tmpdir(), 'toolip-ast-async-wrapper');
    const route = `import { execute } from './queries.js';
export async function handler(req: RequestLike) {
  await execute(req.body.statement);
}`;
    const query = `export async function execute(statement: string) {
  await Promise.resolve(statement).then((value) => db.query(value));
}`;
    const project = createAstProjectAnalysis([
      {
        filePath: 'routes.ts',
        absolutePath: path.join(root, 'routes.ts'),
        content: route
      },
      {
        filePath: 'queries.ts',
        absolutePath: path.join(root, 'queries.ts'),
        content: query
      }
    ]);

    expect(
      analyzeAstSource('queries.ts', query, project).map(
        (finding) => finding.ruleId
      )
    ).toEqual(['TLP-AST-005']);
  });

  it('resolves child_process aliases through immutable project re-exports', () => {
    const root = path.join(os.tmpdir(), 'toolip-ast-child-process-reexports');
    const route = `import { run } from './barrel.js';
run(untrusted);`;
    const inputs = (bridge: string): AstProjectInput[] => [
      {
        filePath: 'route.ts',
        absolutePath: path.join(root, 'route.ts'),
        content: route
      },
      {
        filePath: 'bridge.ts',
        absolutePath: path.join(root, 'bridge.ts'),
        content: bridge
      }
    ];

    for (const [barrel, bridge] of [
      [
        `export { run } from './bridge.js';`,
        `export { exec as run } from 'node:child_process';`
      ],
      [
        `export * from './bridge.js';`,
        `import { exec } from 'node:child_process'; const run = exec; export { run };`
      ]
    ]) {
      const projectInputs = [
        requiredProjectInput(inputs(bridge), 0),
        {
          filePath: 'barrel.ts',
          absolutePath: path.join(root, 'barrel.ts'),
          content: barrel
        },
        requiredProjectInput(inputs(bridge), 1)
      ];
      const project = createAstProjectAnalysis(projectInputs);
      const findings = analyzeAstSource('route.ts', route, project);
      expect(findings.map((finding) => finding.ruleId)).toContain(
        'TLP-AST-003'
      );
    }

    const defaultRoute = `import run from './bridge.js';\nrun(untrusted);`;
    const defaultProject = createAstProjectAnalysis([
      {
        filePath: 'route.ts',
        absolutePath: path.join(root, 'route.ts'),
        content: defaultRoute
      },
      {
        filePath: 'bridge.ts',
        absolutePath: path.join(root, 'bridge.ts'),
        content: `import { exec } from 'node:child_process';\nexport default exec;`
      }
    ]);
    expect(
      analyzeAstSource('route.ts', defaultRoute, defaultProject).map(
        (finding) => finding.ruleId
      )
    ).toContain('TLP-AST-003');

    const typeOnlyProject = createAstProjectAnalysis([
      requiredProjectInput(
        inputs(`export { exec as run } from 'node:child_process';`),
        0
      ),
      {
        filePath: 'barrel.ts',
        absolutePath: path.join(root, 'barrel.ts'),
        content: `export type { run } from './bridge.js';`
      },
      {
        filePath: 'bridge.ts',
        absolutePath: path.join(root, 'bridge.ts'),
        content: `export { exec as run } from 'node:child_process';`
      }
    ]);
    expect(
      analyzeAstSource('route.ts', route, typeOnlyProject).some(
        (finding) => finding.ruleId === 'TLP-AST-003'
      )
    ).toBe(false);

    const resolveBridge = (bridge: string) =>
      createAstProjectAnalysis([
        requiredProjectInput(inputs(bridge), 0),
        {
          filePath: 'barrel.ts',
          absolutePath: path.join(root, 'barrel.ts'),
          content: `export { run } from './bridge.js';`
        },
        requiredProjectInput(inputs(bridge), 1)
      ]);
    const reassignedProject =
      resolveBridge(`import { exec } from 'node:child_process';
let run = exec;
run = (value: string) => value;
export { run };`);
    expect(
      analyzeAstSource('route.ts', route, reassignedProject).some(
        (finding) =>
          finding.ruleId === 'TLP-AST-003' || finding.ruleId === 'TLP-AST-011'
      )
    ).toBe(false);

    const conditionalProject =
      resolveBridge(`import { exec } from 'node:child_process';
let run = (value: string) => value;
if (condition) run = exec;
export { run };`);
    expect(
      analyzeAstSource('route.ts', route, conditionalProject).map(
        (finding) => finding.ruleId
      )
    ).toContain('TLP-AST-011');

    const closureProject =
      resolveBridge(`import { exec } from 'node:child_process';
let run = (value: string) => value;
function promote() { run = exec; }
export { run };`);
    expect(
      analyzeAstSource('route.ts', route, closureProject).map(
        (finding) => finding.ruleId
      )
    ).toContain('TLP-AST-011');

    const shadowedClosureProject = resolveBridge(
      `let run = (value: string) => value;
function unrelated() { let run = require('node:child_process').exec; }
export { run };`
    );
    expect(
      analyzeAstSource('route.ts', route, shadowedClosureProject).some(
        (finding) =>
          finding.ruleId === 'TLP-AST-003' || finding.ruleId === 'TLP-AST-011'
      )
    ).toBe(false);

    const importEqualsRoute = `import childProcess = require('./bridge.js');
childProcess.exec(untrusted);`;
    const importEqualsProject = createAstProjectAnalysis([
      {
        filePath: 'route.ts',
        absolutePath: path.join(root, 'route.ts'),
        content: importEqualsRoute
      },
      {
        filePath: 'bridge.ts',
        absolutePath: path.join(root, 'bridge.ts'),
        content: `export = require('node:child_process');`
      }
    ]);
    expect(
      analyzeAstSource('route.ts', importEqualsRoute, importEqualsProject).map(
        (finding) => finding.ruleId
      )
    ).toContain('TLP-AST-003');
  }, 30_000);

  it('resolves CommonJS child_process re-exports without treating shadowed exports as trusted', () => {
    const root = path.join(os.tmpdir(), 'toolip-ast-child-process-cjs');
    const route = `import { run } from './bridge.cjs';
run(untrusted);`;
    for (const bridge of [
      `const cp = require('node:child_process');\nexports.run = cp.exec;`,
      `const cp = require('node:child_process');\nmodule.exports = { run: cp.exec };`
    ]) {
      const project = createAstProjectAnalysis([
        {
          filePath: 'route.ts',
          absolutePath: path.join(root, 'route.ts'),
          content: route
        },
        {
          filePath: 'bridge.cjs',
          absolutePath: path.join(root, 'bridge.cjs'),
          content: bridge
        }
      ]);

      expect(
        analyzeAstSource('route.ts', route, project).map(
          (finding) => finding.ruleId
        )
      ).toContain('TLP-AST-003');
    }

    const namespaceRoute = `import * as childProcess from './bridge.cjs';
childProcess.exec(untrusted);`;
    const namespaceProject = createAstProjectAnalysis([
      {
        filePath: 'route.ts',
        absolutePath: path.join(root, 'route.ts'),
        content: namespaceRoute
      },
      {
        filePath: 'bridge.cjs',
        absolutePath: path.join(root, 'bridge.cjs'),
        content: `module.exports = require('node:child_process');`
      }
    ]);
    expect(
      analyzeAstSource('route.ts', namespaceRoute, namespaceProject).map(
        (finding) => finding.ruleId
      )
    ).toContain('TLP-AST-003');

    const shadowed = createAstProjectAnalysis([
      {
        filePath: 'route.ts',
        absolutePath: path.join(root, 'route.ts'),
        content: route
      },
      {
        filePath: 'bridge.cjs',
        absolutePath: path.join(root, 'bridge.cjs'),
        content: `const exports = {}; exports.run = (value) => value;`
      }
    ]);
    expect(
      analyzeAstSource('route.ts', route, shadowed).some(
        (finding) => finding.ruleId === 'TLP-AST-003'
      )
    ).toBe(false);
  }, 30_000);

  it('returns an unresolved candidate when a project re-export chain exceeds its depth budget', () => {
    const root = path.join(
      os.tmpdir(),
      'toolip-ast-child-process-deep-reexports'
    );
    const inputs: AstProjectInput[] = [
      {
        filePath: 'route.ts',
        absolutePath: path.join(root, 'route.ts'),
        content: `import { run } from './module-0.js'; run(untrusted);`
      }
    ];
    const moduleCount = 270;
    for (let index = 0; index < moduleCount; index += 1) {
      inputs.push({
        filePath: `module-${index}.ts`,
        absolutePath: path.join(root, `module-${index}.ts`),
        content:
          index + 1 === moduleCount
            ? `export { exec as run } from 'node:child_process';`
            : `export { run } from './module-${index + 1}.js';`
      });
    }

    const project = createAstProjectAnalysis(inputs);
    const firstInput = requiredProjectInput(inputs, 0);
    const findings = analyzeAstSource(
      firstInput.filePath,
      firstInput.content,
      project
    );
    expect(findings.map((finding) => finding.ruleId)).toContain('TLP-AST-011');
  });

  it('keeps project taint analysis complete above the former 2,000-file cutoff', () => {
    const root = path.join(os.tmpdir(), 'toolip-ast-large-project');
    const inputs = Array.from({ length: 2_001 }, (_, index) => {
      const filePath = `src/file-${index}.ts`;
      return {
        filePath,
        absolutePath: path.join(root, filePath),
        content: ''
      };
    });

    const project = createAstProjectAnalysis(inputs);

    expect(project.sourceFiles.size).toBe(inputs.length);
    expect(project.dependencyDigests.size).toBe(inputs.length);
  });

  it('invalidates transitive importers while keeping unrelated AST inputs stable', () => {
    const root = path.join(os.tmpdir(), 'toolip-ast-cache-digests');
    const inputs = (database: string) => [
      {
        filePath: 'routes.ts',
        absolutePath: path.join(root, 'routes.ts'),
        content: `import { execute } from './queries.js';\nexport const run = () => execute();`
      },
      {
        filePath: 'queries.ts',
        absolutePath: path.join(root, 'queries.ts'),
        content: `export { execute } from './database.js';`
      },
      {
        filePath: 'database.ts',
        absolutePath: path.join(root, 'database.ts'),
        content: database
      },
      {
        filePath: 'unrelated.ts',
        absolutePath: path.join(root, 'unrelated.ts'),
        content: 'export const unchanged = 1;'
      }
    ];
    const before = createAstProjectAnalysis(
      inputs('export function execute() { return 1; }')
    );
    const after = createAstProjectAnalysis(
      inputs('export function execute() { return 2; }')
    );

    expect(after.dependencyDigests.get('routes.ts')).not.toBe(
      before.dependencyDigests.get('routes.ts')
    );
    expect(after.dependencyDigests.get('queries.ts')).not.toBe(
      before.dependencyDigests.get('queries.ts')
    );
    expect(after.dependencyDigests.get('database.ts')).not.toBe(
      before.dependencyDigests.get('database.ts')
    );
    expect(after.dependencyDigests.get('unrelated.ts')).toBe(
      before.dependencyDigests.get('unrelated.ts')
    );
  });

  it('keeps parameterized SQL safe when tainted values cross local helpers', () => {
    const findings = analyzeAstSource(
      'routes.ts',
      `function executeQuery(db: Database, id: string) {
  db.query('SELECT * FROM users WHERE id = ?', [id]);
}
function handler(req: RequestLike, db: Database) {
  executeQuery(db, req.query.id);
}`
    );

    expect(findings.some((finding) => finding.ruleId === 'TLP-AST-005')).toBe(
      false
    );
  });

  it('fails closed when nested interprocedural flow exceeds its work budget', () => {
    const depth = 500;
    const nestedCalls = `${'identity('.repeat(depth)}req.query.value${')'.repeat(depth)}`;
    const source =
      `function identity(value: string) { return value; }\n` +
      `function handler(req: RequestLike, db: Database) { db.query(${nestedCalls}); }`;

    expect(() => analyzeAstSource('routes.ts', source)).toThrow(
      'AST taint analysis work budget exceeded'
    );
  });

  it('does not flag parameterized SQL, constant URLs or ordinary assignments', () => {
    const findings = analyzeAstSource(
      'routes.ts',
      `
function handler(req: RequestLike, db: Database) {
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);
  fetch('https://service.example/health');
  element.innerHTML = '<p>Welcome</p>';
  const output: Record<string, string> = {};
  output.label = req.body.label;
}
`
    );

    expect(findings).toEqual([]);
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

  it('integrates the project symbol graph with bounded snapshot reads', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-ast-project-'));
    const route = `import { execute } from './queries.js';
export function handler(req: RequestLike, db: Database) {
  execute(db, req.query.statement);
}`;
    const query = `export { runQuery as execute } from './database.js';`;
    const database = `export function runQuery(db: Database, sql: string) {
  db.query(sql);
}`;

    try {
      await writeFile(path.join(root, 'routes.ts'), route);
      await writeFile(path.join(root, 'queries.ts'), query);
      await writeFile(path.join(root, 'database.ts'), database);
      const result = await new AstSecurityAnalyzer().analyze({ root });
      const finding = result.findings.find(
        (item) => item.ruleId === 'TLP-AST-005'
      );

      expect(result.coverage?.state).toBe('complete');
      expect(result.metadata?.crossFileAnalysis).toBe(
        'complete-for-resolved-snapshot-symbols'
      );
      expect(finding?.location?.file).toBe('database.ts');
      expect(finding?.metadata?.sourceProvenance).toMatchObject({
        path: 'database.ts',
        sha256: createHash('sha256').update(database).digest('hex')
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
