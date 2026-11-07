import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';

describe('GitHub Action integration contract', () => {
  it('uses a pinned composite runtime and emits SARIF without project lifecycle execution', async () => {
    const text = await readFile(path.resolve('action.yml'), 'utf8');
    const document = parseDocument(text);
    expect(document.errors).toEqual([]);
    const action = document.toJS() as {
      runs?: {
        using?: string;
        steps?: Array<{
          uses?: string;
          run?: string;
          if?: string;
          with?: Record<string, string>;
        }>;
      };
    };
    expect(action.runs?.using).toBe('composite');
    const setup = action.runs?.steps?.find((step) => step.uses);
    expect(setup?.uses).toMatch(/^actions\/setup-node@[a-f0-9]{40}$/u);
    const commands = action.runs?.steps
      ?.flatMap((step) => step.run ?? [])
      .join('\n');
    expect(commands).toContain('npm ci --ignore-scripts');
    expect(commands).toContain('npm audit signatures --ignore-scripts');
    expect(commands).toContain('policy check');
    expect(commands).toContain('--sarif');
    expect(commands).not.toMatch(/\b(?:npm|pnpm|yarn)\s+(?:install|ci)(?![^\n]*--ignore-scripts)/u);
    const upload = action.runs?.steps?.find((step) =>
      step.uses?.startsWith('github/codeql-action/upload-sarif@')
    );
    expect(upload?.uses).toMatch(
      /^github\/codeql-action\/upload-sarif@[a-f0-9]{40}$/u
    );
    expect(upload?.if).toContain("inputs.upload-sarif == 'true'");
    expect(upload?.if).toContain('github.event.pull_request.head.repo.fork == false');
    expect(upload?.with?.sarif_file).toBe('$' + '{{ inputs.sarif-output }}');
  });
});
