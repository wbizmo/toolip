import { describe, expect, it } from 'vitest';
import { analyzeAstSource } from '../../src/analyzers/ast/source-analysis.js';

type CorpusCase = {
  name: string;
  ruleId: string;
  expected: boolean;
  source: string;
};

const corpus: CorpusCase[] = [
  {
    name: 'direct imported shell execution',
    ruleId: 'TLP-AST-003',
    expected: true,
    source: `import { exec } from 'node:child_process'; exec(req.query.command);`
  },
  {
    name: 'explicit shell mode for execFile',
    ruleId: 'TLP-AST-010',
    expected: true,
    source: `import { execFile } from 'node:child_process'; execFile('tool', [req.query.command], { shell: true });`
  },
  {
    name: 'request-derived SQL concatenation',
    ruleId: 'TLP-AST-005',
    expected: true,
    source: `db.query('SELECT * FROM users WHERE id=' + req.query.id);`
  },
  {
    name: 'request-derived server URL',
    ruleId: 'TLP-AST-006',
    expected: true,
    source: `await fetch(req.query.url);`
  },
  {
    name: 'request-derived HTML assignment',
    ruleId: 'TLP-AST-007',
    expected: true,
    source: `element.innerHTML = req.query.html;`
  },
  {
    name: 'request-derived object assignment',
    ruleId: 'TLP-AST-008',
    expected: true,
    source: `Object.assign(target, req.body);`
  },
  {
    name: 'unscoped route lookup',
    ruleId: 'TLP-AUTH-001',
    expected: true,
    source: `router.get('/records/:id', async (req, res) => { return prisma.record.findUnique({ where: { id: req.params.id } }); });`
  },
  {
    name: 'authentication-only route guard',
    ruleId: 'TLP-AUTH-001',
    expected: true,
    source: `router.get('/records/:id', async (req, res) => { if (!req.user) throw new Error('unauthorized'); return prisma.record.findUnique({ where: { id: req.params.id } }); });`
  },
  {
    name: 'shadowed exec parameter',
    ruleId: 'TLP-AST-003',
    expected: false,
    source: `import { exec } from 'node:child_process'; function safe(exec: (value: string) => void) { exec(req.query.command); }`
  },
  {
    name: 'reassigned exec alias',
    ruleId: 'TLP-AST-003',
    expected: false,
    source: `import { exec } from 'node:child_process'; let run = exec; run = (value: string) => value; run(req.query.command);`
  },
  {
    name: 'exec alias called before a later reassignment',
    ruleId: 'TLP-AST-003',
    expected: true,
    source: `import { exec } from 'node:child_process'; let run = exec; run(req.query.command); run = (value: string) => value;`
  },
  {
    name: 'conditionally reassigned alias remains a review candidate',
    ruleId: 'TLP-AST-011',
    expected: true,
    source: `import { exec } from 'node:child_process'; let run = (value: string) => value; if (condition) run = exec; run(req.query.command);`
  },
  {
    name: 'conditional reassignment among local functions is not a child-process candidate',
    ruleId: 'TLP-AST-011',
    expected: false,
    source: `let run = (value: string) => value; if (condition) run = (value: string) => value; run(req.query.command);`
  },
  {
    name: 'execFile argument vector without shell',
    ruleId: 'TLP-AST-010',
    expected: false,
    source: `import { execFile } from 'node:child_process'; execFile('tool', [req.query.command]);`
  },
  {
    name: 'parameterized SQL query',
    ruleId: 'TLP-AST-005',
    expected: false,
    source: `db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);`
  },
  {
    name: 'constant server URL',
    ruleId: 'TLP-AST-006',
    expected: false,
    source: `await fetch('https://service.example.test/health');`
  },
  {
    name: 'constant HTML assignment',
    ruleId: 'TLP-AST-007',
    expected: false,
    source: `element.innerHTML = '<p>safe</p>';`
  },
  {
    name: 'static object assignment',
    ruleId: 'TLP-AST-008',
    expected: false,
    source: `Object.assign(target, { enabled: true });`
  },
  {
    name: 'owner-scoped route lookup',
    ruleId: 'TLP-AUTH-001',
    expected: false,
    source: `router.get('/records/:id', async (req, res) => { return prisma.record.findFirst({ where: { id: req.params.id, ownerId: req.user.id } }); });`
  }
];

describe('AST fixed positive/negative corpus', () => {
  it('records measured false-positive and false-negative counts', () => {
    const results = corpus.map((item) => {
      const filePath = `${item.name}.ts`;
      const finding = analyzeAstSource(filePath, item.source).find(
        (candidate) => candidate.ruleId === item.ruleId
      );
      return {
        ...item,
        filePath,
        finding,
        detected: Boolean(finding)
      };
    });
    const falsePositives = results.filter(
      (item) => !item.expected && item.detected
    );
    const falseNegatives = results.filter(
      (item) => item.expected && !item.detected
    );
    const invalidLocations = results
      .filter((item) => item.expected && item.finding)
      .filter((item) => {
        const finding = item.finding;
        if (!finding) return true;
        return (
          finding.location?.file !== item.filePath ||
          finding.location.line !== 1 ||
          !finding.location.column ||
          finding.evidence?.some((evidence) => evidence.excerpt)
        );
      });

    expect({
      cases: results.length,
      positives: results.filter((item) => item.expected).length,
      negatives: results.filter((item) => !item.expected).length,
      falsePositives: falsePositives.map((item) => item.name),
      falseNegatives: falseNegatives.map((item) => item.name),
      invalidLocations: invalidLocations.map((item) => item.name)
    }).toEqual({
      cases: 19,
      positives: 10,
      negatives: 9,
      falsePositives: [],
      falseNegatives: [],
      invalidLocations: []
    });
  });
});
