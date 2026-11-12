import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { OsvVulnerabilityAnalyzer } from '../../src/analyzers/vulnerability/osv-analyzer.js';
import { OsvClient } from '../../src/providers/osv/client.js';
import { ExploitIntelClient } from '../../src/providers/exploit-intel/client.js';
import { AdvisorySnapshotCache } from '../../src/providers/intelligence/snapshot-cache.js';
import { MemoryCache } from '../../src/storage/memory-cache.js';
import { parsePythonTargetProfile } from '../../src/core/dependencies/python-target.js';

function publicNpmSource(name: string, version: string) {
  const tail = name.split('/').at(-1) ?? name;
  return {
    resolved: `https://registry.npmjs.org/${name}/-/${tail}-${version}.tgz`
  };
}

describe('OsvVulnerabilityAnalyzer', () => {
  it('marks manifest-only npm requirements unresolved rather than reporting a clean advisory scan', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-manifest-'));
    let queryCount = 0;
    try {
      await writeFile(
        path.join(root, 'package.json'),
        JSON.stringify({ dependencies: { example: '^1.0.0' } })
      );
      const client = new OsvClient({
        fetchImplementation: async () => {
          queryCount += 1;
          return new Response(JSON.stringify({ results: [] }), { status: 200 });
        }
      });
      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });
      expect(queryCount).toBe(0);
      expect(result.findings).toEqual([]);
      expect(result.coverage?.state).toBe('failed');
      expect(result.warnings).toContainEqual(
        expect.stringContaining('npm-lockfile-missing')
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('queries resolvable exact instances but marks incomplete lock graphs partial', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-partial-'));
    let queryCount = 0;
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: { resolved: '1.2.3', missing: '^2.0.0' }
            },
            'node_modules/resolved': {
              version: '1.2.3',
              ...publicNpmSource('resolved', '1.2.3')
            }
          }
        })
      );
      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as { queries: unknown[] };
          queryCount += body.queries.length;
          return new Response(
            JSON.stringify({
              results: body.queries.map(() => ({
                vulns: [
                  {
                    id: 'GHSA-test-path',
                    summary: 'Partial graph path fixture',
                    database_specific: { severity: 'HIGH' }
                  }
                ]
              }))
            }),
            { status: 200 }
          );
        }
      });
      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });
      expect(queryCount).toBe(1);
      expect(result.metadata?.dependenciesChecked).toBe(1);
      expect(result.coverage?.state).toBe('partial');
      expect(result.findings[0]?.metadata?.remediationPath).toMatchObject({
        dependencyPathStatus: 'partial',
        dependencyPath: [
          { package: 'resolved', version: '1.2.3', direct: true }
        ]
      });
      expect(result.warnings).toContainEqual(
        expect.stringContaining('unresolved npm dependency missing')
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('creates normalized findings', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-'));
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: { 'example-package': '1.0.0' }
            },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );

      const client = new OsvClient({
        fetchImplementation: async () =>
          new Response(
            JSON.stringify({
              results: [
                {
                  vulns: [
                    {
                      id: 'GHSA-test-0001',
                      summary: 'Test vulnerability',
                      database_specific: { severity: 'HIGH' },
                      affected: [
                        {
                          package: {
                            ecosystem: 'npm',
                            name: 'example-package'
                          },
                          ranges: [{ events: [{ fixed: '1.0.1' }] }]
                        }
                      ]
                    },
                    {
                      id: 'GHSA-test-0002',
                      summary: 'Multiple fixed release lines',
                      database_specific: { severity: 'MEDIUM' },
                      affected: [
                        {
                          package: {
                            ecosystem: 'npm',
                            name: 'example-package'
                          },
                          ranges: [
                            {
                              events: [{ fixed: '1.0.2' }, { fixed: '2.0.0' }]
                            }
                          ]
                        }
                      ]
                    },
                    {
                      id: 'GHSA-test-0003',
                      summary: 'Unrelated package has a different fix',
                      database_specific: { severity: 'LOW' },
                      affected: [
                        {
                          package: { ecosystem: 'npm', name: 'other-package' },
                          ranges: [{ events: [{ fixed: '99.0.0' }] }]
                        },
                        {
                          package: {
                            ecosystem: 'npm',
                            name: 'example-package'
                          },
                          ranges: [{ events: [{ introduced: '0' }] }]
                        }
                      ]
                    }
                  ]
                }
              ]
            }),
            { status: 200 }
          )
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root,
        cache: new MemoryCache()
      });

      expect(result.findings).toHaveLength(3);
      const singleFix = result.findings.find(
        (finding) => finding.metadata?.vulnerabilityId === 'GHSA-test-0001'
      );
      const multipleFixes = result.findings.find(
        (finding) => finding.metadata?.vulnerabilityId === 'GHSA-test-0002'
      );
      const unrelatedFix = result.findings.find(
        (finding) => finding.metadata?.vulnerabilityId === 'GHSA-test-0003'
      );
      expect(singleFix?.severity).toBe('high');
      expect(singleFix?.remediation?.fixedVersion).toBe('1.0.1');
      expect(singleFix?.metadata?.remediationPath).toMatchObject({
        target: {
          package: 'example-package',
          installedVersion: '1.0.0',
          installPath: 'node_modules/example-package'
        },
        dependencyPath: [
          {
            package: 'example-package',
            version: '1.0.0',
            installPath: 'node_modules/example-package'
          }
        ],
        dependencyPathStatus: 'verified',
        fixedVersions: ['1.0.1'],
        verificationSteps: expect.arrayContaining([
          expect.stringContaining('frozen install'),
          expect.stringContaining('tests')
        ])
      });
      expect(multipleFixes?.remediation?.fixedVersion).toBeUndefined();
      expect(multipleFixes?.metadata?.remediationPath).toMatchObject({
        fixedVersions: ['1.0.2', '2.0.0']
      });
      expect(unrelatedFix?.remediation?.fixedVersion).toBeUndefined();
      expect(unrelatedFix?.metadata?.remediationPath).toMatchObject({
        fixedVersions: []
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('bounds deep remediation paths while keeping the shortest root prefix', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-deep-path-'));
    try {
      const packageCount = 70;
      const packages: Record<string, Record<string, unknown>> = {
        '': { name: 'fixture', version: '1.0.0', dependencies: { p0: '1.0.0' } }
      };
      let installPath = 'node_modules/p0';
      for (let index = 0; index < packageCount; index += 1) {
        const name = `p${index}`;
        packages[installPath] = {
          version: '1.0.0',
          ...publicNpmSource(name, '1.0.0'),
          ...(index + 1 < packageCount
            ? { dependencies: { [`p${index + 1}`]: '1.0.0' } }
            : {})
        };
        if (index + 1 < packageCount)
          installPath += `/node_modules/p${index + 1}`;
      }
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({ lockfileVersion: 3, packages })
      );
      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as {
            queries: Array<{ package: { name: string } }>;
          };
          return new Response(
            JSON.stringify({
              results: body.queries.map((query) => ({
                vulns:
                  query.package.name === `p${packageCount - 1}`
                    ? [
                        {
                          id: 'GHSA-deep-path',
                          summary: 'Deep dependency path fixture'
                        }
                      ]
                    : []
              }))
            }),
            { status: 200 }
          );
        }
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });
      const pathMetadata = result.findings[0]?.metadata?.remediationPath as
        | {
            dependencyPath: Array<{ package: string }>;
            dependencyPathTruncated: boolean;
            dependencyPathStatus: string;
          }
        | undefined;
      expect(pathMetadata?.dependencyPathStatus).toBe('verified');
      expect(pathMetadata?.dependencyPath).toHaveLength(64);
      expect(pathMetadata?.dependencyPath[0]?.package).toBe('p0');
      expect(pathMetadata?.dependencyPath.at(-1)?.package).toBe('p63');
      expect(pathMetadata?.dependencyPathTruncated).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('queries each unique package version once and maps results to each instance', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-'));
    let queryCount = 0;

    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            },
            'node_modules/parent/node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );

      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as { queries: unknown[] };
          queryCount += body.queries.length;
          return new Response(
            JSON.stringify({
              results: body.queries.map(() => ({
                vulns: [
                  {
                    id: 'GHSA-test-0001',
                    summary: 'Test vulnerability',
                    database_specific: { severity: 'HIGH' }
                  }
                ]
              }))
            }),
            { status: 200 }
          );
        }
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });

      expect(queryCount).toBe(1);
      expect(result.findings).toHaveLength(2);
      expect(new Set(result.findings.map((finding) => finding.id)).size).toBe(
        2
      );
      expect(result.metadata?.uniqueVersionsQueried).toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('joins vulnerability priority to the exact resolved package reachability instance', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-reachability-')
    );
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: { 'example-package': '1.0.0' }
            },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );
      await writeFile(
        path.join(root, 'app.ts'),
        "import { run } from 'example-package';\nrun();\n"
      );
      const packageDirectory = path.join(
        root,
        'node_modules',
        'example-package'
      );
      await import('node:fs/promises').then(({ mkdir }) =>
        mkdir(packageDirectory, { recursive: true })
      );
      await writeFile(
        path.join(packageDirectory, 'package.json'),
        JSON.stringify({
          name: 'example-package',
          version: '1.0.0',
          main: 'index.js'
        })
      );
      await writeFile(
        path.join(packageDirectory, 'index.js'),
        'exports.run = () => {};'
      );
      const client = new OsvClient({
        fetchImplementation: async () =>
          new Response(
            JSON.stringify({
              results: [
                {
                  vulns: [
                    {
                      id: 'GHSA-test-reachability',
                      summary: 'Reachable vulnerable package',
                      database_specific: { severity: 'HIGH' }
                    }
                  ]
                }
              ]
            }),
            { status: 200 }
          )
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });
      expect(result.findings[0]?.metadata?.reachability).toBe('reachable');
      expect(result.findings[0]?.metadata?.riskPriority).toMatchObject({
        reachability: 'reachable',
        factors: expect.arrayContaining(['reachability:reachable'])
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('queries exact non-npm lockfile identities using their OSV ecosystems', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-'));
    let queries: Array<{
      package: { ecosystem: string; name: string };
      version: string;
    }> = [];
    try {
      await writeFile(
        path.join(root, 'Cargo.lock'),
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.188"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
      );
      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as {
            queries: typeof queries;
          };
          queries = body.queries;
          return new Response(
            JSON.stringify({ results: queries.map(() => ({ vulns: [] })) }),
            { status: 200 }
          );
        }
      });
      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });
      expect(result.metadata?.dependenciesChecked).toBe(1);
      expect(queries).toEqual([
        {
          package: { ecosystem: 'crates.io', name: 'serde' },
          version: '1.0.188'
        }
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('withholds public advisory requests when an npm lock entry has no registry origin', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-origin-'));
    let queryCount = 0;
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: { privateLib: '2.0.0' }
            },
            'node_modules/privateLib': { version: '2.0.0' }
          }
        })
      );
      const client = new OsvClient({
        fetchImplementation: async () => {
          queryCount++;
          return new Response(JSON.stringify({ results: [] }), { status: 200 });
        }
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });

      expect(queryCount).toBe(0);
      expect(result.coverage?.state).not.toBe('complete');
      expect(result.warnings).toContain('osv-public-query-withheld:1');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('withholds public PyPI advisory requests for hashed requirements inherited from a custom index', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-python-source-')
    );
    let queryCount = 0;
    try {
      await mkdir(path.join(root, 'requirements'), { recursive: true });
      await writeFile(
        path.join(root, 'requirements.txt'),
        '--index-url https://packages.example.test/simple\n-r requirements/locked.txt\n'
      );
      await writeFile(
        path.join(root, 'requirements/locked.txt'),
        `internal-pkg==1.2.3 --hash=sha256:${'f'.repeat(64)}\n`
      );
      const client = new OsvClient({
        fetchImplementation: async () => {
          queryCount++;
          return new Response(JSON.stringify({ results: [] }), { status: 200 });
        }
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });

      expect(queryCount).toBe(0);
      expect(result.coverage?.state).not.toBe('complete');
      expect(result.warnings).toContain(
        'dependency-graph:dependency-resolution-provenance-unknown:PyPI'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('withholds Pipenv packages from private-index OSV queries without leaking credentials', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-pipfile-private-')
    );
    let queryCount = 0;
    try {
      await writeFile(
        path.join(root, 'Pipfile'),
        [
          '[[source]]',
          'name = "internal"',
          'url = "https://user:token-should-not-leak@packages.example.test/simple"',
          'verify_ssl = true',
          '',
          '[[source]]',
          'name = "pypi"',
          'url = "https://pypi.org/simple"',
          'verify_ssl = true',
          '',
          '[packages]',
          'internal_pkg = "==1.2.3"',
          'git_pkg = { version = "==2.0.0", git = "https://user:token-should-not-leak@git.example.test/team/private.git", ref = "main" }',
          'path_pkg = { version = "==3.0.0", path = "../private/path-pkg", editable = true }',
          'spoofed_pkg = { version = "==4.0.0", git = "https://user:token-should-not-leak@git.example.test/team/spoofed.git", ref = "main" }'
        ].join('\n')
      );
      await writeFile(
        path.join(root, 'Pipfile.lock'),
        JSON.stringify({
          _meta: {
            sources: [
              {
                name: 'internal',
                url: 'https://user:token-should-not-leak@packages.example.test/simple',
                verify_ssl: true
              },
              { name: 'pypi', url: 'https://pypi.org/simple', verify_ssl: true }
            ]
          },
          default: {
            internal_pkg: {
              version: '==1.2.3',
              index: 'internal',
              hashes: [`sha256:${'a'.repeat(64)}`]
            },
            git_pkg: {
              version: '==2.0.0',
              index: 'pypi',
              git: 'https://user:token-should-not-leak@git.example.test/team/private.git',
              ref: 'main',
              hashes: [`sha256:${'b'.repeat(64)}`]
            },
            path_pkg: {
              version: '==3.0.0',
              index: 'pypi',
              hashes: [`sha256:${'c'.repeat(64)}`]
            },
            spoofed_pkg: {
              version: '==4.0.0',
              index: 'pypi',
              hashes: [`sha256:${'d'.repeat(64)}`]
            }
          }
        })
      );
      const client = new OsvClient({
        fetchImplementation: async () => {
          queryCount++;
          return new Response(JSON.stringify({ results: [] }), { status: 200 });
        }
      });
      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });
      expect(queryCount).toBe(0);
      expect(result.coverage?.state).not.toBe('complete');
      expect(result.warnings).toContain(
        'dependency-graph:dependency-resolution-provenance-unknown:PyPI'
      );
      expect(JSON.stringify(result)).not.toContain('token-should-not-leak');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('queries only the Python lock variants selected by the explicit target', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-python-target-')
    );
    const queries: string[] = [];
    try {
      await writeFile(
        path.join(root, 'Pipfile'),
        [
          '[[source]]',
          'name = "pypi"',
          'url = "https://pypi.org/simple"',
          'verify_ssl = true',
          '',
          '[packages]',
          `linux_pkg = { version = "==1.2.3", markers = "sys_platform == 'linux'", index = "pypi" }`,
          `windows_pkg = { version = "==4.5.6", markers = "sys_platform == 'win32'", index = "pypi" }`
        ].join('\n')
      );
      await writeFile(
        path.join(root, 'Pipfile.lock'),
        JSON.stringify({
          _meta: {
            sources: [
              { name: 'pypi', url: 'https://pypi.org/simple', verify_ssl: true }
            ]
          },
          default: {
            linux_pkg: {
              version: '==1.2.3',
              index: 'pypi',
              markers: "sys_platform == 'linux'",
              hashes: [`sha256:${'a'.repeat(64)}`]
            },
            windows_pkg: {
              version: '==4.5.6',
              index: 'pypi',
              markers: "sys_platform == 'win32'",
              hashes: [`sha256:${'b'.repeat(64)}`]
            }
          },
          develop: {}
        })
      );
      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as {
            queries: Array<{
              package: { ecosystem: string; name: string };
              version: string;
            }>;
          };
          queries.push(
            ...body.queries.map(
              ({ package: pkg, version }) =>
                `${pkg.ecosystem}:${pkg.name}@${version}`
            )
          );
          return new Response(
            JSON.stringify({ results: body.queries.map(() => ({})) }),
            { status: 200 }
          );
        }
      });
      const target = parsePythonTargetProfile({
        id: 'py311-linux',
        environment: {
          implementation_name: 'cpython',
          implementation_version: '3.11.9',
          os_name: 'posix',
          platform_machine: 'x86_64',
          platform_python_implementation: 'CPython',
          platform_release: '6.8.0',
          platform_system: 'Linux',
          platform_version: 'test-release',
          python_full_version: '3.11.9',
          python_version: '3.11',
          sys_platform: 'linux'
        }
      });
      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root,
        options: { pythonTarget: target }
      });

      expect(queries).toEqual(['PyPI:linux-pkg@1.2.3']);
      expect(result.coverage?.state).toBe('partial');
      expect(result.warnings).toContain(
        'dependency-graph:pipfile-lock-transitive-edges-unresolved'
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('withholds OSV queries for Cargo path and git packages and reports partial coverage', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-cargo-provenance-')
    );
    let queries: Array<{
      package: { ecosystem: string; name: string };
      version: string;
    }> = [];
    try {
      await writeFile(
        path.join(root, 'Cargo.lock'),
        [
          'version = 3',
          '',
          '[[package]]',
          'name = "local-helper"',
          'version = "1.0.0"',
          '',
          '[[package]]',
          'name = "private-git"',
          'version = "2.0.0"',
          'source = "git+https://user:token@git.example.test/private/repo?access_token=secret#rev"',
          '',
          '[[package]]',
          'name = "serde"',
          'version = "1.0.188"',
          'source = "registry+https://github.com/rust-lang/crates.io-index"',
          `checksum = "${'a'.repeat(64)}"`
        ].join('\n')
      );
      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as {
            queries: typeof queries;
          };
          queries = body.queries;
          return new Response(
            JSON.stringify({ results: queries.map(() => ({ vulns: [] })) }),
            { status: 200 }
          );
        }
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });

      expect(queries).toEqual([
        {
          package: { ecosystem: 'crates.io', name: 'serde' },
          version: '1.0.188'
        }
      ]);
      expect(result.metadata?.dependenciesChecked).toBe(1);
      expect(result.metadata?.uniqueVersionsQueried).toBe(1);
      expect(result.coverage?.state).toBe('partial');
      expect(result.warnings).toContain(
        'dependency-graph:cargo-path-or-workspace-provenance-unverified'
      );
      expect(result.warnings).toContain(
        'dependency-graph:cargo-git-provenance-unverified'
      );
      expect(JSON.stringify(result)).not.toMatch(
        /user:token|access_token|secret|git\.example\.test/iu
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('attaches EPSS and KEV provenance and orders known exploitation above severity alone', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-intel-'));
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );
      const osv = new OsvClient({
        fetchImplementation: async () =>
          new Response(
            JSON.stringify({
              results: [
                {
                  vulns: [
                    {
                      id: 'GHSA-test-0002',
                      aliases: ['CVE-2026-12345'],
                      summary: 'Low-severity exploited issue',
                      database_specific: { severity: 'LOW' }
                    }
                  ]
                }
              ]
            }),
            { status: 200 }
          )
      });
      const intel = new ExploitIntelClient({
        now: () => new Date('2026-11-06T12:00:00.000Z'),
        fetchImplementation: async (input) =>
          new Response(
            JSON.stringify(
              String(input).includes('first.org')
                ? {
                    status: 'OK',
                    data: [
                      {
                        cve: 'CVE-2026-12345',
                        epss: '0.8',
                        percentile: '0.99',
                        date: '2026-11-06'
                      }
                    ]
                  }
                : {
                    catalogVersion: '1.0',
                    dateReleased: '2026-11-06T00:00:00.000Z',
                    vulnerabilities: [
                      {
                        cveID: 'CVE-2026-12345',
                        dateAdded: '2026-11-06'
                      }
                    ]
                  }
            ),
            { status: 200 }
          )
      });

      const result = await new OsvVulnerabilityAnalyzer(osv, intel).analyze({
        root
      });
      const finding = result.findings[0];
      expect(finding?.severity).toBe('low');
      expect(finding?.metadata?.exploitIntel).toMatchObject({
        status: 'available',
        knownExploited: true,
        epss: { probability: 0.8, percentile: 0.99 }
      });
      expect(finding?.metadata?.riskPriority).toMatchObject({
        knownExploited: true,
        epssProbability: 0.8,
        dataCompleteness: 'complete',
        unknownFactors: []
      });
      expect(
        Number(
          (finding?.metadata?.riskPriority as { score: number } | undefined)
            ?.score
        )
      ).toBeGreaterThan(60);
      expect(result.metadata?.exploitIntel).toMatchObject({
        status: 'available',
        cvesChecked: 1
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('labels unavailable exploit-intelligence factors instead of implying zero risk', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-intel-unknown-')
    );
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );
      const osv = new OsvClient({
        fetchImplementation: async () =>
          new Response(
            JSON.stringify({
              results: [
                {
                  vulns: [
                    {
                      id: 'GHSA-test-unknown',
                      aliases: ['CVE-2026-12345'],
                      summary: 'Known advisory with unavailable exploit data',
                      database_specific: { severity: 'HIGH' }
                    }
                  ]
                }
              ]
            }),
            { status: 200 }
          )
      });
      const unavailableIntel = {
        lookup: async (cves: string[]) => ({
          status: 'unavailable' as const,
          fetchedAt: 'unknown',
          epssStatus: 'unavailable' as const,
          kevStatus: 'unavailable' as const,
          queriedCves: cves.length,
          records: new Map(),
          warnings: ['provider-outage']
        })
      } as unknown as ExploitIntelClient;

      const result = await new OsvVulnerabilityAnalyzer(
        osv,
        unavailableIntel
      ).analyze({ root });

      expect(result.findings[0]?.metadata?.riskPriority).toMatchObject({
        epssStatus: 'unavailable',
        kevStatus: 'unavailable',
        dataCompleteness: 'unknown',
        unknownFactors: ['epss:unavailable', 'kev:unavailable'],
        context: {
          direct: false,
          development: false,
          optional: false
        }
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('combines multiple CVE aliases without losing the strongest EPSS or KEV evidence', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-aliases-'));
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );
      const osv = new OsvClient({
        fetchImplementation: async () =>
          new Response(
            JSON.stringify({
              results: [
                {
                  vulns: [
                    {
                      id: 'GHSA-test-0003',
                      aliases: ['CVE-2026-12345', 'CVE-2026-23456'],
                      summary: 'Multi-alias issue',
                      database_specific: { severity: 'LOW' }
                    }
                  ]
                }
              ]
            }),
            { status: 200 }
          )
      });
      const intel = new ExploitIntelClient({
        now: () => new Date('2026-11-06T12:00:00.000Z'),
        fetchImplementation: async (input) =>
          new Response(
            JSON.stringify(
              String(input).includes('first.org')
                ? {
                    status: 'OK',
                    data: [
                      {
                        cve: 'CVE-2026-12345',
                        epss: '0.4',
                        percentile: '0.8',
                        date: '2026-11-06'
                      },
                      {
                        cve: 'CVE-2026-23456',
                        epss: '0.9',
                        percentile: '0.99',
                        date: '2026-11-06'
                      }
                    ]
                  }
                : {
                    catalogVersion: '1.0',
                    dateReleased: '2026-11-06T00:00:00.000Z',
                    vulnerabilities: [
                      {
                        cveID: 'CVE-2026-23456',
                        dateAdded: '2026-11-06'
                      }
                    ]
                  }
            ),
            { status: 200 }
          )
      });

      const result = await new OsvVulnerabilityAnalyzer(osv, intel).analyze({
        root
      });
      expect(result.findings[0]?.metadata?.exploitIntel).toMatchObject({
        status: 'available',
        matchedCves: ['CVE-2026-12345', 'CVE-2026-23456'],
        knownExploited: true,
        epss: { probability: 0.9 },
        kev: { source: 'CISA KEV', added: '2026-11-06' }
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('uses an offline OSV snapshot without network access and reports missing records as incomplete', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-offline-'));
    const snapshotRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-snap-')
    );
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );
      let requests = 0;
      const client = new OsvClient({
        fetchImplementation: async () => {
          requests++;
          throw new Error('offline lookup attempted network access');
        }
      });
      const keys = generateKeyPairSync('ed25519');
      const privateKey = keys.privateKey
        .export({ type: 'pkcs8', format: 'pem' })
        .toString();
      const publicKey = keys.publicKey
        .export({ type: 'spki', format: 'pem' })
        .toString();
      const snapshot = await AdvisorySnapshotCache.open(
        path.join(snapshotRoot, 'advisories.json'),
        {
          now: () => new Date('2026-11-06T12:00:00.000Z'),
          signingPrivateKeyPem: privateKey,
          signingKeyId: 'test-key'
        }
      );
      await snapshot.set('osv:v1:npm:example-package@1.0.0', {
        query: {
          package: { ecosystem: 'npm', name: 'example-package' },
          version: '1.0.0'
        },
        vulnerabilities: []
      });
      await snapshot.flush();
      const verifiedSnapshot = await AdvisorySnapshotCache.open(
        snapshot.filePath,
        {
          now: () => new Date('2026-11-06T12:00:00.000Z'),
          trustedPublicKeyPem: publicKey,
          requireSignature: true
        }
      );

      const analyzer = new OsvVulnerabilityAnalyzer(client);
      const complete = await analyzer.analyze({
        root,
        cache: verifiedSnapshot,
        options: { offline: true }
      });
      expect(requests).toBe(0);
      expect(complete.coverage?.state).toBe('partial');
      expect(complete.warnings).toContainEqual(
        expect.stringContaining('dependency-install-location-unavailable')
      );
      expect(complete.metadata?.advisoryData).toMatchObject({
        mode: 'offline',
        missingRecords: 0
      });

      const missing = await new OsvVulnerabilityAnalyzer(client).analyze({
        root,
        options: { offline: true }
      });
      expect(requests).toBe(0);
      expect(missing.coverage?.state).toBe('failed');
      expect(missing.warnings).toContain('osv-snapshot-missing:1');
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(snapshotRoot, { recursive: true, force: true });
    }
  });

  it('marks stale offline OSV records incomplete rather than as current coverage', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-stale-'));
    const snapshotRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-stale-snap-')
    );
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );
      const snapshotPath = path.join(snapshotRoot, 'advisories.json');
      const keys = generateKeyPairSync('ed25519');
      const privateKey = keys.privateKey
        .export({ type: 'pkcs8', format: 'pem' })
        .toString();
      const publicKey = keys.publicKey
        .export({ type: 'spki', format: 'pem' })
        .toString();
      const writer = await AdvisorySnapshotCache.open(snapshotPath, {
        now: () => new Date('2026-01-01T00:00:00.000Z'),
        signingPrivateKeyPem: privateKey,
        signingKeyId: 'test-key'
      });
      await writer.set('osv:v1:npm:example-package@1.0.0', {
        query: {
          package: { ecosystem: 'npm', name: 'example-package' },
          version: '1.0.0'
        },
        vulnerabilities: []
      });
      await writer.flush();
      const snapshot = await AdvisorySnapshotCache.open(snapshotPath, {
        now: () => new Date('2026-11-06T12:00:00.000Z'),
        trustedPublicKeyPem: publicKey,
        requireSignature: true
      });

      const result = await new OsvVulnerabilityAnalyzer().analyze({
        root,
        cache: snapshot,
        options: {
          offline: true,
          maxAdvisoryAgeMs: 24 * 60 * 60 * 1000
        }
      });
      expect(result.coverage?.state).toBe('partial');
      expect(result.warnings).toContain('osv-snapshot-stale:1');
      expect(Date.parse(snapshot.generatedAt ?? '')).toBe(
        Date.parse('2026-01-01T00:00:00.000Z')
      );
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(snapshotRoot, { recursive: true, force: true });
    }
  });

  it('does not trust a hash-only offline snapshot as a vulnerability all-clear', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-untrusted-'));
    const snapshotRoot = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-untrusted-snapshot-')
    );
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'fixture', version: '1.0.0' },
            'node_modules/example-package': {
              version: '1.0.0',
              ...publicNpmSource('example-package', '1.0.0')
            }
          }
        })
      );
      const snapshotPath = path.join(snapshotRoot, 'advisories.json');
      const writer = await AdvisorySnapshotCache.open(snapshotPath);
      await writer.set('osv:v1:npm:example-package@1.0.0', {
        query: {
          package: { ecosystem: 'npm', name: 'example-package' },
          version: '1.0.0'
        },
        vulnerabilities: []
      });
      await writer.flush();
      const snapshot = await AdvisorySnapshotCache.open(snapshotPath);
      const result = await new OsvVulnerabilityAnalyzer().analyze({
        root,
        cache: snapshot,
        options: { offline: true }
      });

      expect(result.coverage?.state).toBe('failed');
      expect(result.warnings).toContain(
        'advisory-snapshot-signature-unverified:1'
      );
      expect(result.warnings).toContain('osv-snapshot-missing:1');
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(snapshotRoot, { recursive: true, force: true });
    }
  });

  it('withholds scoped and custom-registry npm identifiers from OSV without explicit consent', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-private-'));
    let requests = 0;
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: {
                '@private/secret': '1.0.0',
                'custom-library': '2.0.0'
              }
            },
            'node_modules/@private/secret': { version: '1.0.0' },
            'node_modules/custom-library': {
              version: '2.0.0',
              resolved:
                'https://packages.example.test/custom-library/-/custom-library-2.0.0.tgz'
            }
          }
        })
      );
      const client = new OsvClient({
        fetchImplementation: async () => {
          requests += 1;
          return new Response(JSON.stringify({ results: [] }), {
            status: 200
          });
        }
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });

      expect(requests).toBe(0);
      expect(result.coverage?.state).toBe('failed');
      expect(result.warnings).toContain('osv-public-query-withheld:2');
      expect(result.metadata?.advisoryData).toMatchObject({
        privacyRestrictedRecords: 2
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('queries a public scoped package only after explicit consent', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-public-scope-')
    );
    let queriedNames: string[] = [];
    try {
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0',
              dependencies: { '@public/library': '^1.0.0' }
            },
            'node_modules/@public/library': {
              version: '1.0.0',
              resolved:
                'https://registry.npmjs.org/@public%2flibrary/-/library-1.0.0.tgz'
            }
          }
        })
      );
      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as {
            queries: Array<{ package: { name: string } }>;
          };
          queriedNames = body.queries.map((query) => query.package.name);
          return new Response(
            JSON.stringify({
              results: body.queries.map(() => ({ vulns: [] }))
            }),
            { status: 200 }
          );
        }
      });

      await new OsvVulnerabilityAnalyzer(client).analyze({
        root,
        options: { allowPublicScope: true }
      });

      expect(queriedNames).toEqual(['@public/library']);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('queries exact Python, Go, Cargo, Maven and Packagist identities through OSV', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-osv-ecosystems-')
    );
    const queried = new Map<string, string[]>();
    try {
      await writeFile(
        path.join(root, 'requirements.txt'),
        'requests==2.31.0\nignored>=99.0\n'
      );
      await writeFile(
        path.join(root, 'go.mod'),
        'module example.test/app\nrequire example.test/lib v1.2.3\n'
      );
      await writeFile(
        path.join(root, 'go.sum'),
        'example.test/lib v1.2.3 h1:YWJjZA==\n'
      );
      await writeFile(
        path.join(root, 'Cargo.lock'),
        `version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.188"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${'a'.repeat(64)}"\n`
      );
      await writeFile(
        path.join(root, 'maven-dependency-tree.txt'),
        '[INFO] app:service:jar:1.0.0\n[INFO] +- org.example:core:jar:tests:4.2.0:compile\n'
      );
      await writeFile(
        path.join(root, 'composer.lock'),
        JSON.stringify({
          packages: [
            { name: 'vendor/library', version: '1.2.0' },
            { name: 'vendor/branch', version: 'dev-main' }
          ]
        })
      );
      await writeFile(
        path.join(root, 'composer.json'),
        JSON.stringify({
          require: {
            'vendor/library': '^1.0',
            'vendor/branch': 'dev-main'
          }
        })
      );
      const client = new OsvClient({
        fetchImplementation: async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as {
            queries: Array<{
              package: { ecosystem: string; name: string };
              version: string;
            }>;
          };
          for (const query of body.queries) {
            const versions = queried.get(query.package.ecosystem) ?? [];
            versions.push(`${query.package.name}@${query.version}`);
            queried.set(query.package.ecosystem, versions);
          }
          return new Response(
            JSON.stringify({
              results: body.queries.map((query) => ({
                vulns:
                  (query.package.ecosystem === 'PyPI' &&
                    query.package.name === 'requests') ||
                  (query.package.ecosystem === 'Go' &&
                    query.package.name === 'example.test/lib')
                    ? [
                        {
                          id: 'PYSEC-2024-1',
                          summary: 'Test Python advisory',
                          database_specific: { severity: 'HIGH' }
                        }
                      ]
                    : []
              }))
            }),
            { status: 200 }
          );
        }
      });

      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root
      });

      expect(result.coverage?.state).toBe('partial');
      expect(result.warnings).toContain(
        'dependency-graph:python-requirements-are-declared-pins:requirements.txt'
      );
      expect(queried.get('PyPI')).toContain('requests@2.31.0');
      expect(
        queried.has('PyPI') &&
          queried.get('PyPI')?.some((value) => value.startsWith('ignored@'))
      ).toBe(false);
      expect(
        queried.get('Go')?.includes('example.test/lib@v1.2.3') ?? false
      ).toBe(false);
      expect(queried.get('crates.io')).toContain('serde@1.0.188');
      expect(queried.get('Maven')).toContain('org.example:core@4.2.0');
      expect(queried.get('Packagist')).toContain('vendor/library@1.2.0');
      expect(queried.get('Packagist')).not.toContain('vendor/branch@dev-main');
      expect(result.warnings).toContain(
        'dependency-graph:composer-branch-version-unverified:vendor/branch'
      );
      const declaredPinFinding = result.findings.find(
        (finding) => finding.metadata?.package === 'requests'
      );
      expect(declaredPinFinding?.metadata).toMatchObject({
        resolutionConfidence: 'declared-pin',
        declaredVersion: '2.31.0'
      });
      expect(declaredPinFinding?.metadata).not.toHaveProperty(
        'installedVersion'
      );
      const goFinding = result.findings.find(
        (finding) => finding.metadata?.package === 'example.test/lib'
      );
      expect(goFinding).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('queries the MVS-selected Go version only through explicit tool execution', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-osv-go-mvs-'));
    const goModSum = `h1:${Buffer.alloc(32, 5).toString('base64')}`;
    const files = {
      'package.json': JSON.stringify({ name: 'app', version: '1.0.0' }),
      'go.mod': [
        'module example.test/app',
        'go 1.24.0',
        'require example.test/lib v1.2.0'
      ].join('\n'),
      'go.sum': `example.test/lib v1.3.0/go.mod ${goModSum}\n`
    };
    const fileSource = {
      files: Object.keys(files),
      hasFile: (relativePath: string) => relativePath in files,
      readText: (relativePath: string) =>
        files[relativePath as keyof typeof files]
    };
    const queried: string[] = [];
    const runner = async (input: {
      cwd: string;
      args: readonly string[];
    }): Promise<string> => {
      if (input.args[0] === 'version') return 'go version go1.24.1 linux/amd64';
      if (input.args[0] === 'list') {
        await writeFile(
          path.join(input.cwd, 'go.sum'),
          `example.test/lib v1.3.0/go.mod ${goModSum}\n`
        );
        return [
          JSON.stringify({ Path: 'example.test/app', Main: true }),
          JSON.stringify({
            Path: 'example.test/lib',
            Version: 'v1.3.0',
            GoModSum: goModSum
          })
        ].join('\n');
      }
      return 'example.test/app example.test/lib@v1.3.0\n';
    };
    const client = new OsvClient({
      fetchImplementation: async (_input, init) => {
        const request = JSON.parse(String(init?.body)) as {
          queries: Array<{
            package: { ecosystem: string; name: string };
            version: string;
          }>;
        };
        queried.push(
          ...request.queries.map(
            (query) =>
              `${query.package.ecosystem}:${query.package.name}@${query.version}`
          )
        );
        return new Response(
          JSON.stringify({
            results: request.queries.map(() => ({
              vulns: [
                {
                  id: 'GO-2026-1000',
                  summary: 'Selected Go module advisory',
                  database_specific: { severity: 'HIGH' }
                }
              ]
            }))
          }),
          { status: 200 }
        );
      }
    });
    try {
      const result = await new OsvVulnerabilityAnalyzer(client).analyze({
        root,
        options: {
          dependencyFileSource: fileSource,
          allowGoToolExecution: true,
          goCommandRunner: runner
        }
      });
      expect(queried).toContain('Go:example.test/lib@v1.3.0');
      expect(result.findings[0]?.metadata).toMatchObject({
        package: 'example.test/lib',
        installedVersion: 'v1.3.0',
        resolutionConfidence: 'lockfile'
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
