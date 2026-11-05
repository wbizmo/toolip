import { afterEach, describe, expect, it } from 'vitest';
import { runGitAudit } from '../../src/core/git-audit.js';
import {
  cleanupRepos,
  git,
  makeRepo,
  tempDir,
  write
} from '../helpers/git-repo.js';

afterEach(cleanupRepos);

const ids = (r: Awaited<ReturnType<typeof runGitAudit>>) =>
  r.findings.map((f) => f.id);
const has = (r: Awaited<ReturnType<typeof runGitAudit>>, part: string) =>
  ids(r).some((id) => id.includes(part));

// Issue #42: protection was inferred from substrings of .gitignore lines.
describe('git-audit uses Git behavior, not .gitignore text (issue #42)', () => {
  it('does not count a negated `!.env` rule as protective', async () => {
    const root = makeRepo();
    write(root, '.gitignore', '.env\n!.env\n*.pem\n');
    write(root, '.env', 'A=1\n');

    const result = await runGitAudit(root);
    expect(result.summary.envIgnored).toBe(false);
    expect(has(result, 'ENV-NOT-IGNORED')).toBe(true);
    expect(
      result.findings.find((f) => f.id.includes('ENV-NOT-IGNORED'))
        ?.evidence?.[0]?.summary
    ).toMatch(/Observed with git check-ignore/u);
  });

  it('does not accept unrelated substrings, comments or lookalike patterns', async () => {
    const root = makeRepo();
    write(
      root,
      '.gitignore',
      '# .env is ignored below\n.environment\nmy.env.txt\nenv\n*.pemx\n'
    );

    const result = await runGitAudit(root);
    expect(result.summary.envIgnored).toBe(false);
    expect(result.summary.pemIgnored).toBe(false);
    expect(has(result, 'ENV-NOT-IGNORED')).toBe(true);
    expect(has(result, 'PEM-NOT-IGNORED')).toBe(true);
  });

  it('accepts real ignore rules and nested .gitignore files', async () => {
    const good = makeRepo();
    write(good, '.gitignore', '.env\n.env.*\n!.env.example\n*.pem\n*.key\n');
    const ok = await runGitAudit(good);
    expect(ok.summary.envIgnored).toBe(true);
    expect(ok.summary.pemIgnored).toBe(true);
    expect(has(ok, 'NOT-IGNORED')).toBe(false);
    expect(ok.summary.ignoreStatus).toBe('observed');

    // A nested rule cannot protect the root: root .env stays unprotected.
    const nested = makeRepo();
    write(nested, '.gitignore', '*.pem\n*.key\n');
    write(nested, 'pkg/.gitignore', '.env\n.env.*\n');
    write(nested, '.env', 'A=1\n');
    write(nested, 'pkg/.env', 'A=1\n');
    const result = await runGitAudit(nested);
    expect(result.summary.envIgnored).toBe(false);
    expect(has(result, 'ENV-NOT-IGNORED')).toBe(true);
  });

  it('reports tracked sensitive files even when an ignore rule matches them', async () => {
    const root = makeRepo();
    write(root, '.gitignore', '.env\n.env.*\n*.pem\n*.key\n');
    write(root, '.env', 'A=1\n');
    write(root, 'certs/server.pem', 'not a real key\n');
    git(root, 'add', '-f', '.env', 'certs/server.pem');
    git(root, 'commit', '-q', '-m', 'oops');

    const result = await runGitAudit(root);
    expect(result.summary.envIgnored).toBe(true); // the rule works…
    expect(result.summary.trackedSensitiveFiles).toBe(2); // …but does not protect tracked files
    const env = result.findings.find((f) => f.id.includes('TRACKED-ENV-FILE'));
    const pem = result.findings.find((f) => f.id.includes('TRACKED-PEM-FILE'));
    expect(env?.severity).toBe('high');
    expect(env?.evidence?.[0]?.summary).toContain('git ls-files');
    expect(pem?.severity).toBe('critical');
    expect(pem?.location?.file).toBe('certs/server.pem');
  });

  it('allows tracked .env.example style templates', async () => {
    const root = makeRepo();
    write(root, '.gitignore', '.env\n.env.*\n!.env.example\n');
    for (const name of [
      '.env.example',
      '.env.sample',
      'apps/web/.env.template'
    ]) {
      write(root, name, 'A=\n');
    }
    git(root, 'add', '-f', '-A');
    git(root, 'commit', '-q', '-m', 'templates');

    const result = await runGitAudit(root);
    expect(result.summary.trackedSensitiveFiles).toBe(0);
    expect(has(result, 'ENV-FILE')).toBe(false);
  });

  it('reports unknown, not safe or unsafe, outside a Git work tree', async () => {
    const root = tempDir('toolip-nogit-');
    write(root, '.gitignore', 'node_modules\n');
    write(root, '.env', 'A=1\n');

    const result = await runGitAudit(root);
    expect(result.summary.ignoreStatus).toBe('unknown');
    expect(result.summary.envIgnored).toBe(false);
    expect(has(result, 'STATUS-UNKNOWN')).toBe(true);
    expect(
      result.findings.find((f) => f.id.includes('STATUS-UNKNOWN'))?.message
    ).toContain('not inside a Git work tree');
    expect(has(result, 'NOT-IGNORED')).toBe(false); // nothing guessed
    expect(has(result, 'TRACKED')).toBe(false);
  });

  it('keeps reporting a missing .gitignore as policy presence only', async () => {
    const root = makeRepo();
    const result = await runGitAudit(root);
    expect(result.summary.gitignorePresent).toBe(false);
    expect(has(result, 'MISSING-GITIGNORE')).toBe(true);
  });
});
