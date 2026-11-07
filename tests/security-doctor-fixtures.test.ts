import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runSecurityDoctor } from '../src/core/security-doctor.js';
import { AnalysisResultCache } from '../src/application/task-scheduler.js';

describe('security doctor hardening', () => {
  it('includes final-stage Docker findings in the shared security scan', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-docker-integrated-')
    );
    try {
      await writeFile(path.join(root, 'package.json'), '{}');
      await writeFile(
        path.join(root, 'Dockerfile'),
        [
          'FROM node:20 AS builder',
          'USER builder',
          'RUN npm run build',
          'FROM node:20-slim AS runtime',
          'CMD ["node", "server.js"]'
        ].join('\n')
      );

      const result = await runSecurityDoctor(root);

      expect(result.docker.files).toBe(1);
      expect(result.docker.coverage.state).toBe('complete');
      expect(result.findings.map((finding) => finding.ruleId)).toContain(
        'TLP-DOCKER-001'
      );
      expect(result.findings.map((finding) => finding.ruleId)).toContain(
        'TLP-DOCKER-006'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('detects npm tokens', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-npm-token-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      const token = `npm_${'1'.repeat(28)}`;
      await writeFile(path.join(root, 'index.ts'), `const token = "${token}";`);

      const result = await runSecurityDoctor(root);

      expect(
        result.findings.some((finding) =>
          finding.id.includes('TOOLIP-SECRET-NPM-TOKEN')
        )
      ).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('does not create findings for clean code', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-clean-project-'));

    try {
      await writeFile(path.join(root, 'package.json'), '{}');

      await writeFile(
        path.join(root, 'index.ts'),
        `
export function sum(a: number, b: number) {
  return a + b;
}
`
      );

      const result = await runSecurityDoctor(root);

      const criticalOrHigh = result.findings.filter(
        (finding) =>
          finding.severity === 'critical' || finding.severity === 'high'
      );

      expect(criticalOrHigh.length).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('invalidates imported taint dependents while reusing unrelated cached files', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-project-taint-'));
    const cache = new AnalysisResultCache();
    const route = `import { execute } from './queries.js';
export function handler(req: RequestLike, db: Database) {
  execute(db, req.query.statement);
}`;
    const query = `export { runQuery as execute } from './database.js';`;
    const unsafeDatabase = `export function runQuery(db: Database, sql: string) {
  db.query(sql);
}`;

    try {
      await writeFile(path.join(root, 'routes.ts'), route);
      await writeFile(path.join(root, 'queries.ts'), query);
      await writeFile(path.join(root, 'database.ts'), unsafeDatabase);
      await writeFile(
        path.join(root, 'independent.ts'),
        'export const unchanged = 1;'
      );
      await writeFile(path.join(root, 'notes.txt'), 'No security content.');
      const first = await runSecurityDoctor(root, { analysisCache: cache });
      expect(
        first.findings.some((finding) => finding.ruleId === 'TLP-AST-005')
      ).toBe(true);

      await writeFile(
        path.join(root, 'database.ts'),
        `export function runQuery(db: Database, id: string) {
  db.query('SELECT * FROM users WHERE id = ?', [id]);
}`
      );
      const second = await runSecurityDoctor(root, { analysisCache: cache });

      expect(
        second.findings.some((finding) => finding.ruleId === 'TLP-AST-005')
      ).toBe(false);
      expect(second.cacheMetrics.hits).toBe(2);
      expect(second.cacheMetrics.misses).toBe(3);
      expect(second.coverage.state).toBe('complete');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
