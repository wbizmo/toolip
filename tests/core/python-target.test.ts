import { describe, expect, it } from 'vitest';
import {
  evaluatePythonMarkerExpression,
  parsePythonTargetProfile,
  parsePythonTargetProfileJson,
  pythonVersionSatisfies
} from '../../src/core/dependencies/python-target.js';

function profile(
  overrides: Record<string, string> = {},
  extras: string[] = []
) {
  return parsePythonTargetProfile({
    id: 'py312-linux',
    environment: {
      implementation_name: 'cpython',
      implementation_version: '3.12.4',
      os_name: 'posix',
      platform_machine: 'x86_64',
      platform_python_implementation: 'CPython',
      platform_release: '6.8.0',
      platform_system: 'Linux',
      platform_version: '#1 SMP',
      python_full_version: '3.12.4',
      python_version: '3.12',
      sys_platform: 'linux',
      ...overrides
    },
    extras
  });
}

describe('Python target profiles and marker evaluation', () => {
  it('requires a complete, bounded and unambiguous marker environment', () => {
    expect(() =>
      parsePythonTargetProfile({
        id: 'bad',
        environment: { python_version: '3.12' }
      })
    ).toThrow('every marker environment value');
    expect(() =>
      parsePythonTargetProfile({
        id: 'bad',
        environment: {
          implementation_name: 'cpython',
          implementation_version: '3.12',
          os_name: 'posix',
          platform_machine: 'x86_64',
          platform_python_implementation: 'CPython',
          platform_release: '6.8',
          platform_system: 'Linux',
          platform_version: 'release',
          python_full_version: '3.12',
          python_version: '3.12',
          sys_platform: 'linux',
          injected: 'value'
        }
      })
    ).toThrow('every marker environment value');
    expect(() => parsePythonTargetProfileJson('x'.repeat(4097))).toThrow(
      'exceeds 4 KiB'
    );
  });

  it('evaluates marker boolean precedence, target values, and optional extras', () => {
    const linux = profile({}, ['docs']);
    expect(
      evaluatePythonMarkerExpression(
        "python_version >= '3.12' and sys_platform == 'linux' or os_name == 'nt'",
        linux
      )
    ).toBe(true);
    expect(
      evaluatePythonMarkerExpression(
        "os_name == 'nt' or platform_system == 'Linux'",
        linux
      )
    ).toBe(true);
    expect(
      evaluatePythonMarkerExpression("extra == 'docs'", linux, linux.extras)
    ).toBe(true);
    expect(evaluatePythonMarkerExpression("extra == 'test'", linux, [])).toBe(
      false
    );
    expect(
      evaluatePythonMarkerExpression("'test' in dependency_groups", linux)
    ).toBe(undefined);
    expect(
      evaluatePythonMarkerExpression(
        "extra == 'fast'",
        linux,
        Array.from({ length: 65 }, (_, index) => `extra-${index}`)
      )
    ).toBe(undefined);
    expect(
      evaluatePythonMarkerExpression(
        "python_version < '3.12' and os_name == 'nt'",
        linux
      )
    ).toBe(false);
  });

  it('uses PEP 440 ordering and compatible/wildcard version operators', () => {
    const candidate = profile({
      python_version: '3.11',
      python_full_version: '3.11.0rc2'
    });
    expect(
      evaluatePythonMarkerExpression("python_full_version < '3.11'", candidate)
    ).toBe(true);
    expect(
      evaluatePythonMarkerExpression("python_version == '3.11.*'", candidate)
    ).toBe(true);
    expect(
      evaluatePythonMarkerExpression("python_version ~= '3.11.2'", candidate)
    ).toBe(false);
    expect(
      evaluatePythonMarkerExpression("python_version ~= '3.10'", candidate)
    ).toBe(true);
    expect(
      evaluatePythonMarkerExpression("python_version ~= '3'", candidate)
    ).toBe(undefined);
    expect(pythonVersionSatisfies('1.0.0', '==1.0')).toBe(true);
    expect(pythonVersionSatisfies('1.0.0rc1', '<1.0')).toBe(false);
    expect(pythonVersionSatisfies('1.2.4.post1', '~=1.2.3')).toBe(true);
    expect(pythonVersionSatisfies('1.3.0', '~=1.2.3')).toBe(false);
    expect(pythonVersionSatisfies('2!1.0', '>1!9.0')).toBe(true);
    expect(pythonVersionSatisfies('1.2.4', '==1.2.*')).toBe(true);
    expect(pythonVersionSatisfies('1.3.0', '==1.2.*')).toBe(false);
    expect(pythonVersionSatisfies('1.2.4', '^1.2')).toBe(undefined);
    expect(pythonVersionSatisfies('1.0+ABC.1', '==1.0+abc.1')).toBe(true);
    expect(pythonVersionSatisfies('1.0+local', '==1.0')).toBe(true);
    expect(pythonVersionSatisfies('1.0+local', '!=1.0')).toBe(false);
    expect(pythonVersionSatisfies('1.2.0rc1', '>=1.0')).toBe(false);
    expect(pythonVersionSatisfies('1.2.0rc1', '>=1.2.0rc1')).toBe(true);
    expect(pythonVersionSatisfies('1.2.3+local', '>=1.2.3')).toBe(true);
    const postDev = profile({
      implementation_version: '1.0.post1.dev1',
      python_full_version: '1.0.post1.dev1',
      python_version: '1.0'
    });
    expect(
      evaluatePythonMarkerExpression("python_full_version > '1.0'", postDev)
    ).toBe(true);
    expect(pythonVersionSatisfies('1.999999999999999999999.0', '>=1.0')).toBe(
      undefined
    );
    expect(pythonVersionSatisfies('999999999999999999999!1.0', '>=1.0')).toBe(
      undefined
    );
  });

  it('returns unknown for invalid or unsupported marker expressions', () => {
    const target = profile();
    expect(
      evaluatePythonMarkerExpression("python_version = '3.12'", target)
    ).toBe(undefined);
    expect(
      evaluatePythonMarkerExpression(
        `python_version == '${'3.'.repeat(600)}'`,
        target
      )
    ).toBe(undefined);
  });
});
