import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  assessNodeRuntime,
  decideRuntimeAccess,
  NODE_PATCH_FLOORS
} from '../../src/core/runtime-check.js';

const read = <T>(file: string): T =>
  JSON.parse(readFileSync(file, 'utf8')) as T;

describe('assessNodeRuntime (issue #92)', () => {
  it.each(['22.23.4', '22.24.0', '24.22.1', '24.22.2', 'v24.30.0'])(
    'accepts patched %s',
    (version) => {
      expect(assessNodeRuntime(version).status).toBe('ok');
    }
  );

  it.each(['22.23.3', '22.22.2', '24.22.0', '24.15.0', '22.0.0'])(
    'rejects unpatched %s',
    (version) => {
      expect(assessNodeRuntime(version).status).toBe('unpatched');
    }
  );

  it.each(['23.11.0', '25.0.0', '26.12.1', '20.19.0', '21.7.3'])(
    'never admits unsupported major %s',
    (version) => {
      expect(assessNodeRuntime(version).status).toBe('unsupported-major');
    }
  );

  it('fails closed on unparseable versions', () => {
    expect(assessNodeRuntime('not-a-version').status).toBe('invalid');
    expect(assessNodeRuntime('').status).toBe('invalid');
  });

  it('keeps floors, engines and the reviewed policy file in sync', () => {
    const policy = read<{ floors: Record<string, string> }>(
      'security/runtime-floors.json'
    );
    expect(
      Object.fromEntries(
        Object.entries(NODE_PATCH_FLOORS).map(([k, v]) => [k, v])
      )
    ).toEqual(policy.floors);
    expect(
      read<{ engines: { node: string } }>('package.json').engines.node
    ).toBe('^22.23.4 || >=24.22.1 <25');
  });
});

describe('decideRuntimeAccess', () => {
  const unpatched = assessNodeRuntime('22.23.3');

  it('blocks scanning commands on an unpatched runtime by default', () => {
    const decision = decideRuntimeAccess(unpatched, {
      informational: false,
      override: false
    });
    expect(decision.allow).toBe(false);
    expect(decision.error).toContain('does not patch the Node.js binary');
  });

  it('allows informational commands with a warning so users can upgrade', () => {
    const decision = decideRuntimeAccess(unpatched, {
      informational: true,
      override: false
    });
    expect(decision.allow).toBe(true);
    expect(decision.warning).toBeDefined();
  });

  it('allows an explicit operator override but still warns', () => {
    const decision = decideRuntimeAccess(unpatched, {
      informational: false,
      override: true
    });
    expect(decision).toMatchObject({ allow: true });
    expect(decision.warning).toBeDefined();
  });

  it('is silent on a patched runtime', () => {
    expect(
      decideRuntimeAccess(assessNodeRuntime('24.22.2'), {
        informational: false,
        override: false
      })
    ).toEqual({ allow: true });
  });
});
