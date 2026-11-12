import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  readOtherEcosystemInventory,
  readOtherEcosystemInventoryDetailed
} from '../../src/core/dependencies/ecosystem-inventory.js';
import { parsePythonTargetProfile } from '../../src/core/dependencies/python-target.js';
import { parseGoTargetProfile } from '../../src/core/dependencies/go-target.js';

const roots: string[] = [];
afterEach(async () =>
  Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  )
);
async function fixture(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-ecosystems-'));
  roots.push(root);
  return root;
}

function pythonTarget(
  id: string,
  overrides: Record<string, string> = {},
  extras: string[] = []
) {
  return parsePythonTargetProfile({
    id,
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
      sys_platform: 'linux',
      ...overrides
    },
    extras
  });
}

describe('non-npm lockfile inventory', () => {
  it('resolves Pipenv direct requirements only from public exact lock entries', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Pipfile'),
      [
        '[[source]]',
        'name = "pypi"',
        'url = "https://pypi.org/simple"',
        'verify_ssl = true',
        '',
        '[packages]',
        'requests = ">=2.31,<3"',
        'conditional = { version = "==2.0.0", markers = "sys_platform == \'win32\'" }',
        '',
        '[dev-packages]',
        'pytest = "==8.0.0"'
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
          requests: {
            version: '==2.31.0',
            index: 'pypi',
            hashes: [`sha256:${'a'.repeat(64)}`]
          },
          conditional: {
            version: '==2.0.0',
            index: 'pypi',
            markers: "sys_platform == 'win32'"
          }
        },
        develop: {
          pytest: { version: '==8.0.0', index: 'pypi' }
        }
      })
    );
    const graph = await readOtherEcosystemInventoryDetailed(root, undefined, {
      pythonTarget: pythonTarget('py312-linux', {
        implementation_version: '3.12.2',
        python_full_version: '3.12.2',
        python_version: '3.12'
      })
    });
    expect(graph.packages).toContainEqual(
      expect.objectContaining({
        name: 'requests',
        version: '2.31.0',
        source: 'Pipfile.lock:pypi',
        resolutionConfidence: 'lockfile',
        artifactIntegrityStatus: 'declared-not-verified',
        resolutionTarget: 'py312-linux'
      })
    );
    expect(graph.packages.some((item) => item.name === 'conditional')).toBe(
      false
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        name: 'requests',
        requirement: '>=2.31,<3'
      })
    );
    expect(graph.edges.some((edge) => edge.name === 'conditional')).toBe(false);
    expect(graph.warnings).toContain(
      'pipfile-lock-transitive-edges-unresolved'
    );
    expect(graph.complete).toBe(false);
  });

  it('withholds Pipenv entries from private indexes and invalid declared hashes', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Pipfile'),
      [
        '[[source]]',
        'name = "internal"',
        'url = "https://user:secret@packages.example.test/simple"',
        'verify_ssl = true',
        '',
        '[packages]',
        'internal_pkg = "==1.2.3"'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'Pipfile.lock'),
      JSON.stringify({
        _meta: {
          sources: [
            {
              name: 'internal',
              url: 'https://user:secret@packages.example.test/simple',
              verify_ssl: true
            }
          ]
        },
        default: {
          internal_pkg: {
            version: '==1.2.3',
            index: 'internal',
            hashes: ['not-a-digest']
          }
        }
      })
    );
    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(
      graph.packages.find((item) => item.name === 'internal-pkg')
    ).toMatchObject({ resolutionConfidence: 'unknown' });
    expect(graph.edges.some((edge) => edge.name === 'internal-pkg')).toBe(
      false
    );
    expect(graph.warnings).toContain('pipfile-lock-source-unverified');
    expect(graph.warnings).toContain('pipfile-lock-hash-invalid');
    expect(JSON.stringify(graph)).not.toContain('secret');
  });

  it('leaves unsupported Poetry and lockfile dependency groups unresolved', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pyproject.toml'),
      [
        '[tool.poetry]',
        'name = "consumer"',
        'version = "1.0.0"',
        '',
        '[tool.poetry.group.docs.dependencies]',
        'guide = "^1.0"'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'poetry.lock'),
      [
        '[[package]]',
        'name = "guide"',
        'version = "1.2.0"',
        'groups = ["docs"]'
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root, undefined, {
      pythonTarget: pythonTarget('py312-linux')
    });
    expect(graph.packages.find((item) => item.name === 'guide')).toMatchObject({
      resolutionConfidence: 'unknown'
    });
    expect(graph.edges.some((edge) => edge.name === 'guide')).toBe(false);
    expect(graph.warnings).toContain(
      'python-lock-dependency-groups-unresolved:poetry.lock'
    );
    expect(graph.warnings).toContain(
      'python-dependency-group-selection-unresolved'
    );
    expect(graph.complete).toBe(false);
  });

  it('maps Python ranges to one matching locked instance without inventing versions', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pyproject.toml'),
      [
        '[tool.poetry]',
        'name = "consumer"',
        'version = "1.0.0"',
        '',
        '[tool.poetry.dependencies]',
        'python = "^3.11"',
        'parent = "^1.0"',
        'shared = ">=1.0,<2.0"',
        'wide = "~=1.4"'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'poetry.lock'),
      [
        '[[package]]',
        'name = "parent"',
        'version = "1.4.2"',
        '',
        '[package.dependencies]',
        'shared = ">=1.0,<2.0"',
        '',
        '[[package]]',
        'name = "shared"',
        'version = "1.8.0"',
        '',
        '[[package]]',
        'name = "shared"',
        'version = "2.1.0"',
        '[[package]]',
        'name = "wide"',
        'version = "1.8.0"',
        '',
        '[[package]]',
        'name = "wide"',
        'version = "2.1.0"'
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    const parent = graph.packages.find((item) => item.name === 'parent');
    const shared = graph.packages.find(
      (item) => item.name === 'shared' && item.version === '1.8.0'
    );
    const wide = graph.packages.find(
      (item) => item.name === 'wide' && item.version === '1.8.0'
    );
    expect(parent?.version).toBe('1.4.2');
    expect(shared).toBeDefined();
    expect(graph.packages.some((item) => item.version.includes('>='))).toBe(
      false
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: parent?.id,
        name: 'parent',
        requirement: '^1.0'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: shared?.id,
        name: 'shared',
        requirement: '>=1.0,<2.0'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: parent?.id,
        to: shared?.id,
        name: 'shared',
        requirement: '>=1.0,<2.0'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: wide?.id,
        name: 'wide',
        requirement: '~=1.4'
      })
    );
    expect(graph.warnings).not.toContain(
      'unresolved-PyPI-root-dependency:shared'
    );
  });

  it('preserves uv marker variants, extras, and exact dependency edges', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pyproject.toml'),
      [
        '[project]',
        'name = "consumer"',
        'version = "1.0.0"',
        'dependencies = ["shared[tls]>=1.0; python_version < \'3.12\'"]',
        '',
        '[project.optional-dependencies]',
        'accelerated = ["fastlib>=2.0.0"]'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'uv.lock'),
      [
        'version = 1',
        '',
        '[[package]]',
        'name = "consumer"',
        'version = "1.0.0"',
        'source = { editable = "." }',
        'dependencies = [',
        '  { name = "shared", version = "==1.0.0", marker = "python_version < \'3.12\'", extras = ["tls"] }',
        ']',
        '',
        '[package.optional-dependencies]',
        'accelerated = [{ name = "fastlib", version = "==2.0.0" }]',
        '',
        '[[package]]',
        'name = "shared"',
        'version = "1.0.0"',
        'source = { registry = "https://pypi.org/simple" }',
        'resolution-markers = ["python_version < \'3.12\'"]',
        '',
        '[[package]]',
        'name = "shared"',
        'version = "1.0.0"',
        'source = { registry = "https://pypi.org/simple" }',
        'resolution-markers = ["python_version >= \'3.12\'"]',
        '',
        '[[package]]',
        'name = "fastlib"',
        'version = "2.0.0"',
        'source = { registry = "https://pypi.org/simple" }'
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root, undefined, {
      pythonTarget: pythonTarget('py311-linux', {}, ['accelerated'])
    });
    const variants = graph.packages.filter((item) => item.name === 'shared');
    expect(variants).toHaveLength(1);
    expect(new Set(variants.map((item) => item.id)).size).toBe(1);
    expect(variants.every((item) => item.source === 'uv.lock:pypi')).toBe(true);
    expect(variants[0]?.resolutionTarget).toBe('py311-linux');
    expect(variants[0]?.resolutionContext).toContain("< '3.12'");
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        name: 'shared',
        marker: "python_version < '3.12'",
        extras: ['tls']
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        name: 'shared',
        section: 'dependency',
        marker: "python_version < '3.12'",
        extras: ['tls']
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        name: 'fastlib',
        from: expect.stringContaining('consumer@1.0.0'),
        section: 'optionalDependency',
        extras: ['accelerated'],
        resolutionTarget: 'py311-linux'
      })
    );
    expect(graph.packages).toContainEqual(
      expect.objectContaining({
        name: 'consumer',
        resolutionConfidence: 'workspace',
        workspace: 'root'
      })
    );
    expect(graph.warnings).not.toContain(
      'python-source-provenance-unverified:uv.lock'
    );
    expect(graph.complete).toBe(true);

    const windowsGraph = await readOtherEcosystemInventoryDetailed(
      root,
      undefined,
      {
        pythonTarget: pythonTarget(
          'py312-windows',
          {
            implementation_version: '3.12.2',
            os_name: 'nt',
            platform_machine: 'AMD64',
            platform_release: '11',
            platform_system: 'Windows',
            platform_version: '10.0',
            python_full_version: '3.12.2',
            python_version: '3.12',
            sys_platform: 'win32'
          },
          []
        )
      }
    );
    const windowsShared = windowsGraph.packages.filter(
      (item) => item.name === 'shared'
    );
    expect(windowsShared).toHaveLength(1);
    expect(windowsShared[0]?.resolutionTarget).toBe('py312-windows');
    expect(windowsShared[0]?.resolutionContext).toContain(">= '3.12'");
    expect(windowsGraph.edges.some((edge) => edge.name === 'shared')).toBe(
      false
    );

    const unselectedGraph = await readOtherEcosystemInventoryDetailed(root);
    expect(unselectedGraph.complete).toBe(false);
    expect(unselectedGraph.warnings).toContain(
      'python-target-profile-required'
    );
    expect(
      unselectedGraph.packages
        .filter((item) => item.name === 'shared')
        .every((item) => item.resolutionConfidence === 'unknown')
    ).toBe(true);
  });

  it('marks malformed Python environment markers incomplete instead of resolving them', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pyproject.toml'),
      [
        '[project]',
        'name = "consumer"',
        'version = "1.0.0"',
        'dependencies = ["shared>=1.0; python_version ??? \'3.12\'", "other==1.0; python_version = \'3.12\'", "tight==1.0; python_version<\'3.12\'"]'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'poetry.lock'),
      [
        '[[package]]',
        'name = "shared"',
        'version = "1.2.0"',
        '',
        '[[package]]',
        'name = "other"',
        'version = "1.0.0"',
        '',
        '[[package]]',
        'name = "tight"',
        'version = "1.0.0"'
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain(
      'python-requirement-marker-invalid:shared'
    );
    expect(graph.warnings).toContain('python-requirement-marker-invalid:other');
    expect(graph.warnings).toContain('python-requirement-marker-invalid:tight');
    expect(
      graph.edges.some((edge) => edge.from === 'root' && edge.name === 'shared')
    ).toBe(false);

    await writeFile(
      path.join(root, 'pyproject.toml'),
      '[project]\nname = "consumer"\nversion = "1.0.0"\n'
    );
    await writeFile(
      path.join(root, 'uv.lock'),
      [
        'version = 1',
        '',
        '[[package]]',
        'name = "shared"',
        'version = "1.2.0"',
        'source = { registry = "https://pypi.org/simple" }',
        'resolution-markers = ["python_version ??? \'3.12\'"]'
      ].join('\n')
    );
    const invalidLockContext = await readOtherEcosystemInventoryDetailed(root);
    expect(invalidLockContext.complete).toBe(false);
    expect(invalidLockContext.warnings).toContain(
      'python-lock-marker-context-invalid:uv.lock'
    );
  });

  it('resolves declared uv workspace members and connects exact member dependencies', async () => {
    const root = await fixture();
    await mkdir(path.join(root, 'packages', 'worker'), { recursive: true });
    await writeFile(
      path.join(root, 'pyproject.toml'),
      [
        '[project]',
        'name = "workspace-root"',
        'version = "1.0.0"',
        '',
        '[tool.uv.workspace]',
        'members = ["packages/*"]'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'packages', 'worker', 'pyproject.toml'),
      [
        '[project]',
        'name = "worker"',
        'version = "1.0.0"',
        'dependencies = ["requests>=2.30,<3"]'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'uv.lock'),
      [
        'version = 1',
        '',
        '[[package]]',
        'name = "workspace-root"',
        'version = "1.0.0"',
        'source = { editable = "." }',
        '',
        '[[package]]',
        'name = "worker"',
        'version = "1.0.0"',
        'source = { editable = "packages/worker" }',
        '',
        '[[package]]',
        'name = "requests"',
        'version = "2.31.0"',
        'source = { registry = "https://pypi.org/simple" }'
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    const worker = graph.packages.find(
      (item) => item.name === 'worker' && item.workspace === 'packages/worker'
    );
    const requests = graph.packages.find(
      (item) => item.name === 'requests' && item.version === '2.31.0'
    );

    expect(worker).toBeDefined();
    expect(requests).toMatchObject({ direct: true });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: worker?.id,
        to: requests?.id,
        module: 'packages/worker',
        name: 'requests',
        requirement: '>=2.30,<3'
      })
    );
    expect(graph.warnings).not.toContain(
      'ecosystem-workspace-graph-incomplete'
    );
    expect(graph.complete).toBe(true);
  });

  it('matches adversarial uv workspace globs with bounded dynamic programming', async () => {
    const root = await fixture();
    const directory = 'a'.repeat(100);
    await mkdir(path.join(root, directory), { recursive: true });
    await writeFile(
      path.join(root, 'pyproject.toml'),
      `[tool.uv.workspace]\nmembers = ["${'a*'.repeat(100)}b"]\n`
    );
    await writeFile(
      path.join(root, directory, 'pyproject.toml'),
      '[project]\nname = "worker"\nversion = "1.0.0"\n'
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(
      graph.warnings.some((warning) =>
        /^python-workspace-member-pattern-unmatched:/u.test(warning)
      )
    ).toBe(true);
    expect(graph.warnings).toContain('python-resolved-lock-graph-unavailable');
    expect(graph.complete).toBe(false);
  });

  it('marks Cargo workspace matching incomplete when its work budget is exhausted', async () => {
    const root = await fixture();
    const pattern = 'a'.repeat(512);
    const files = new Map<string, string>([
      ['Cargo.toml', `[workspace]\nmembers = ["${pattern}"]\n`]
    ]);
    for (let index = 0; index < 128; index++) {
      const directory = `packages/${'b'.repeat(256)}/${index}`;
      files.set(
        `${directory}/Cargo.toml`,
        `[package]\nname = "member-${index}"\nversion = "1.0.0"\n`
      );
    }
    const fileSource = {
      files: [...files.keys()],
      hasFile: (relativePath: string) => files.has(relativePath),
      readText: (relativePath: string) => files.get(relativePath)
    };
    const graph = await readOtherEcosystemInventoryDetailed(root, fileSource);
    expect(graph.warnings).toContain(
      'cargo-workspace-pattern-work-budget-exceeded'
    );
    expect(graph.complete).toBe(false);
  });

  it('marks Cargo declaration correlation incomplete when duplicate contexts exhaust its budget', async () => {
    const root = await fixture();
    const declarations = Array.from(
      { length: 100 },
      (_, index) => `dep-${index} = { package = "shared", version = "1.0.0" }`
    );
    const lockedDependencies = Array.from(
      { length: 100 },
      () => '"shared 1.0.0"'
    );
    const files = new Map<string, string>([
      ['Cargo.toml', '[workspace]\nmembers = ["packages/*"]\n'],
      [
        'Cargo.lock',
        [
          'version = 3',
          '',
          '[[package]]',
          'name = "shared"',
          'version = "1.0.0"',
          'source = "registry+https://github.com/rust-lang/crates.io-index"',
          `checksum = "${'a'.repeat(64)}"`,
          ...Array.from({ length: 30 }, (_, index) => [
            '',
            '[[package]]',
            `name = "workspace-${index}"`,
            'version = "1.0.0"',
            'dependencies = [',
            ...lockedDependencies.map((dependency) => `  ${dependency},`),
            ']'
          ]).flat()
        ].join('\n')
      ]
    ]);
    for (let index = 0; index < 30; index++) {
      files.set(
        `packages/workspace-${index}/Cargo.toml`,
        [
          '[package]',
          `name = "workspace-${index}"`,
          'version = "1.0.0"',
          '',
          '[dependencies]',
          ...declarations
        ].join('\n')
      );
    }
    const fileSource = {
      files: [...files.keys()],
      hasFile: (relativePath: string) => files.has(relativePath),
      readText: (relativePath: string) => files.get(relativePath)
    };

    const graph = await readOtherEcosystemInventoryDetailed(root, fileSource);

    expect(graph.warnings).toContain(
      'cargo-workspace-declaration-work-budget-exceeded'
    );
    expect(graph.complete).toBe(false);
  });

  it('fails closed when duplicate ecosystem candidates exhaust resolver work', async () => {
    const root = await fixture();
    const lockedCandidates = Array.from({ length: 1_000 }, (_, index) => ({
      name: 'vendor/shared',
      version: `1.${index}.0`
    }));
    const files = new Map<string, string>([
      [
        'composer.json',
        JSON.stringify({
          repositories: [{ type: 'path', url: 'packages/*' }]
        })
      ],
      ['composer.lock', JSON.stringify({ packages: lockedCandidates })]
    ]);
    for (let index = 0; index < 300; index++) {
      const directory = `packages/workspace-${index}`;
      files.set(
        `${directory}/composer.json`,
        JSON.stringify({
          name: `workspace/package-${index}`,
          version: '1.0.0',
          require: { 'vendor/shared': '*' }
        })
      );
    }
    const fileSource = {
      files: [...files.keys()],
      hasFile: (relativePath: string) => files.has(relativePath),
      readText: (relativePath: string) => files.get(relativePath)
    };

    const graph = await readOtherEcosystemInventoryDetailed(root, fileSource);

    expect(graph.warnings).toContain(
      'ecosystem-resolution-work-budget-exceeded'
    );
    expect(graph.complete).toBe(false);
  });

  it('keeps Cargo path and git identities but marks their provenance unknown and redacted', async () => {
    const root = await fixture();
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
    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');
    const graph = await readOtherEcosystemInventoryDetailed(root);
    const byName = new Map(graph.packages.map((item) => [item.name, item]));

    expect(byName.get('local-helper')).toMatchObject({
      resolutionConfidence: 'unknown',
      source: 'Cargo.lock:path-or-workspace-unverified'
    });
    expect(byName.get('private-git')).toMatchObject({
      resolutionConfidence: 'unknown',
      source: expect.stringMatching(
        /^Cargo\.lock:git-unverified:[a-f0-9]{16}$/u
      )
    });
    expect(byName.get('serde')).toMatchObject({
      resolutionConfidence: 'lockfile',
      source: 'Cargo.lock:registry:crates.io',
      integrity: 'a'.repeat(64)
    });
    expect(JSON.stringify(graph)).not.toMatch(
      /user:token|access_token|secret|git\.example\.test/iu
    );
    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain(
      'cargo-path-or-workspace-provenance-unverified'
    );
    expect(graph.warnings).toContain('cargo-git-provenance-unverified');
  });

  it('resolves Cargo workspace members, direct edges, requested features, and target cfg', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Cargo.toml'),
      [
        '[workspace]',
        'members = ["crates/*"]',
        '',
        '[workspace.package]',
        'version = "0.1.0"',
        '',
        '[workspace.dependencies]',
        'serde = { version = "1.0", features = ["derive"] }'
      ].join('\n')
    );
    await mkdir(path.join(root, 'crates/app'), { recursive: true });
    await mkdir(path.join(root, 'crates/utils'), { recursive: true });
    await writeFile(
      path.join(root, 'crates/app/Cargo.toml'),
      [
        '[package]',
        'name = "app"',
        'version = { workspace = true }',
        '',
        '[dependencies]',
        'serde = { workspace = true }',
        'serde-v2 = { package = "serde", version = "2.0", optional = true }',
        'utils = { path = "../utils" }',
        '',
        '[target."cfg(unix)".dependencies]',
        'platform-helper = { version = "1.0", features = ["fast"] }',
        '',
        '[features]',
        'default = ["serde/derive"]'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'crates/utils/Cargo.toml'),
      '[package]\nname = "utils"\nversion = "0.1.0"\n'
    );
    await writeFile(
      path.join(root, 'Cargo.lock'),
      [
        'version = 4',
        '',
        '[[package]]',
        'name = "app"',
        'version = "0.1.0"',
        'dependencies = ["serde 1.0.188", "serde 2.0.0", "utils 0.1.0", "platform-helper 1.0.0"]',
        '',
        '[[package]]',
        'name = "utils"',
        'version = "0.1.0"',
        '',
        '[[package]]',
        'name = "serde"',
        'version = "1.0.188"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'a'.repeat(64)}"`,
        '',
        '[[package]]',
        'name = "serde"',
        'version = "2.0.0"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'c'.repeat(64)}"`,
        '',
        '[[package]]',
        'name = "platform-helper"',
        'version = "1.0.0"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'b'.repeat(64)}"`
      ].join('\n')
    );

    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');
    const graph = await readOtherEcosystemInventoryDetailed(root);
    const workspace = graph.packages.find((item) => item.name === 'app');
    const serde = graph.packages.find((item) => item.name === 'serde');
    const serdeV2 = graph.packages.find(
      (item) => item.name === 'serde' && item.version === '2.0.0'
    );
    const platformHelper = graph.packages.find(
      (item) => item.name === 'platform-helper'
    );

    expect(workspace).toMatchObject({
      version: '0.1.0',
      workspace: 'crates/app',
      resolutionConfidence: 'workspace',
      declaredFeatures: ['default']
    });
    expect(serde).toMatchObject({
      version: '1.0.188',
      direct: true,
      resolutionConfidence: 'lockfile'
    });
    expect(platformHelper).toMatchObject({ direct: true });
    expect(serdeV2).toMatchObject({ version: '2.0.0', direct: true });
    expect(serdeV2?.id).not.toBe(serde?.id);
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: serde?.id,
        name: 'serde',
        requestedFeatures: ['derive']
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: serdeV2?.id,
        name: 'serde',
        alias: 'serde-v2',
        section: 'optionalDependency'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: platformHelper?.id,
        target: 'cfg(unix)'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: workspace?.id,
        to: expect.stringContaining('utils@0.1.0'),
        name: 'utils'
      })
    );
    expect(graph.warnings).not.toContain(
      'ecosystem-workspace-graph-incomplete'
    );
    expect(graph.warnings).toContain(
      'cargo-active-feature-target-selection-unverified:crates/app/Cargo.toml'
    );
    expect(graph.complete).toBe(false);
  });

  it('does not guess installed Cargo identities from unsupported lock formats', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Cargo.toml'),
      '[package]\nname = "fixture"\nversion = "1.0.0"\n'
    );
    await writeFile(
      path.join(root, 'Cargo.lock'),
      'version = 2\n\n[[package]]\nname = "serde"\nversion = "1.0.188"\n'
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(graph.packages).toEqual([]);
    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain('cargo-lock-version-unsupported');
  });

  it('rejects Cargo lock entries with invalid crate names or non-semver versions', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Cargo.lock'),
      [
        'version = 4',
        '',
        '[[package]]',
        'name = "../serde"',
        'version = "1.0.0"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'a'.repeat(64)}"`,
        '',
        '[[package]]',
        'name = "serde"',
        'version = "latest"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'b'.repeat(64)}"`
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages).toEqual([]);
    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain('toml-lock-package-unresolved:Cargo.lock');
  });

  it('marks duplicate exact lock identities with conflicting checksums unknown', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Cargo.lock'),
      [
        'version = 3',
        '',
        '[[package]]',
        'name = "serde"',
        'version = "1.0.188"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'a'.repeat(64)}"`,
        '',
        '[[package]]',
        'name = "serde"',
        'version = "1.0.188"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'b'.repeat(64)}"`
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain(
      'ecosystem-lock-identity-conflict:crates.io:serde'
    );
    expect(graph.packages).toHaveLength(1);
    expect(graph.packages[0]).toMatchObject({
      name: 'serde',
      resolutionConfidence: 'unknown'
    });
    expect(graph.packages[0]?.integrity).toBeUndefined();
  });

  it('marks duplicate exact lock identities with conflicting dependency edges unknown', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Cargo.lock'),
      [
        'version = 3',
        '',
        '[[package]]',
        'name = "serde"',
        'version = "1.0.188"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'a'.repeat(64)}"`,
        'dependencies = ["itoa 1.0.9"]',
        '',
        '[[package]]',
        'name = "serde"',
        'version = "1.0.188"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        `checksum = "${'a'.repeat(64)}"`,
        'dependencies = ["ryu 1.0.15"]'
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain(
      'ecosystem-lock-identity-conflict:crates.io:serde'
    );
    expect(graph.packages).toHaveLength(1);
    expect(graph.packages[0]).toMatchObject({
      name: 'serde',
      resolutionConfidence: 'unknown'
    });
    expect(graph.packages[0]?.integrity).toBeUndefined();
  });

  it('resolves hashed pip-tools pins without merging extras or marker variants', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'requirements.txt'),
      [
        '# generated lock fixture',
        '--index-url https://pypi.org/simple',
        'Shared_Pkg[fast]==1.0.0 ; python_version < "3.12" \\',
        `  --hash=sha256:${'a'.repeat(64)}`,
        'Shared_Pkg[fast]==2.0.0 ; python_version >= "3.12" \\',
        `  --hash=sha256:${'b'.repeat(64)}`
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root, undefined, {
      pythonTarget: pythonTarget('py311-linux')
    });
    const shared = graph.packages.filter((item) => item.name === 'shared-pkg');
    expect(shared).toHaveLength(1);
    expect(shared.map((item) => item.version)).toEqual(['1.0.0']);
    expect(shared[0]).toMatchObject({
      resolutionConfidence: 'lockfile',
      resolutionTarget: 'py311-linux',
      artifactIntegrityStatus: 'declared-not-verified'
    });
    expect(new Set(shared.map((item) => item.id)).size).toBe(1);
    expect(JSON.parse(shared[0]?.resolutionContext ?? '{}')).toEqual({
      markers: ['python_version < "3.12"'],
      extras: ['fast'],
      hashes: [`sha256:${'a'.repeat(64)}`]
    });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: shared[0]?.id,
        marker: 'python_version < "3.12"',
        extras: ['fast']
      })
    );
    expect(graph.complete).toBe(true);

    const py312Graph = await readOtherEcosystemInventoryDetailed(
      root,
      undefined,
      {
        pythonTarget: pythonTarget('py312-linux', {
          implementation_version: '3.12.1',
          python_full_version: '3.12.1',
          python_version: '3.12'
        })
      }
    );
    expect(
      py312Graph.packages.filter((item) => item.name === 'shared-pkg')
    ).toMatchObject([
      {
        version: '2.0.0',
        artifactIntegrityStatus: 'declared-not-verified'
      }
    ]);
  });

  it('keeps unhashed requirement pins as declarations and excludes constraint-only identities', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'requirements.in'), 'Requests==2.31.0\n');
    await writeFile(
      path.join(root, 'constraints-private.txt'),
      [
        '--index-url https://packages.example.test/simple',
        'internal_pkg==4.2.0 \\',
        `  --hash=sha256:${'c'.repeat(64)}`
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(graph.packages).toContainEqual(
      expect.objectContaining({
        name: 'requests',
        version: '2.31.0',
        resolutionConfidence: 'declared-pin'
      })
    );
    expect(graph.packages.some((item) => item.name === 'internal-pkg')).toBe(
      false
    );
    expect(graph.warnings).toContain(
      'python-requirements-source-unverified:constraints-private.txt'
    );
    expect(graph.warnings).toContain(
      'python-constraints-not-installed-identities:constraints-private.txt'
    );
    expect(graph.complete).toBe(false);

    const constraintsOnlyRoot = await fixture();
    await writeFile(
      path.join(constraintsOnlyRoot, 'constraints.txt'),
      'only-a-constraint==9.9.9\n'
    );
    const constraintsOnly =
      await readOtherEcosystemInventoryDetailed(constraintsOnlyRoot);
    expect(constraintsOnly.packages).toEqual([]);
    expect(constraintsOnly.warnings).toContain(
      'python-constraints-not-installed-identities:constraints.txt'
    );
    expect(constraintsOnly.complete).toBe(false);
  });

  it('resolves bounded nested pip requirement includes without treating constraints as installed', async () => {
    const root = await fixture();
    await mkdir(path.join(root, 'requirements'), { recursive: true });
    await writeFile(
      path.join(root, 'requirements.txt'),
      '-r requirements/locked.txt\n-c constraints.txt\n'
    );
    await writeFile(
      path.join(root, 'requirements/locked.txt'),
      `example==1.2.3 --hash=sha256:${'d'.repeat(64)}\n`
    );
    await writeFile(path.join(root, 'constraints.txt'), 'other==4.5.6\n');

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages).toMatchObject([
      {
        name: 'example',
        version: '1.2.3',
        resolutionConfidence: 'lockfile',
        source: 'requirements/locked.txt:pip-compile'
      }
    ]);
    expect(graph.packages.some((item) => item.name === 'other')).toBe(false);
    expect(graph.warnings).toContain(
      'python-constraints-not-installed-identities:constraints.txt'
    );
    expect(graph.complete).toBe(false);
  });

  it('propagates a custom source from a parent pip requirements file to hashed includes', async () => {
    const root = await fixture();
    await mkdir(path.join(root, 'requirements'), { recursive: true });
    await writeFile(
      path.join(root, 'requirements.txt'),
      '--index-url https://packages.example.test/simple\n-r requirements/locked.txt\n'
    );
    await writeFile(
      path.join(root, 'requirements/locked.txt'),
      `internal-pkg==1.2.3 --hash=sha256:${'f'.repeat(64)}\n`
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages).toContainEqual(
      expect.objectContaining({
        name: 'internal-pkg',
        version: '1.2.3',
        resolutionConfidence: 'unknown',
        source: expect.stringContaining('source-unverified')
      })
    );
    expect(graph.warnings).toContain(
      'python-requirements-source-unverified:requirements/locked.txt'
    );
    expect(graph.complete).toBe(false);
  });

  it('rejects root-escaping pip requirement includes and terminates include cycles', async () => {
    const root = await fixture();
    await mkdir(path.join(root, 'nested'), { recursive: true });
    await writeFile(
      path.join(root, 'requirements.txt'),
      '-r nested/cycle.txt\n-r ../../outside.txt\n'
    );
    await writeFile(
      path.join(root, 'nested/cycle.txt'),
      `-r ../requirements.txt\ncycle==2.0.0 --hash=sha256:${'e'.repeat(64)}\n`
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages.filter((item) => item.name === 'cycle')).toHaveLength(
      1
    );
    expect(graph.warnings).toContain(
      'python-requirements-include-outside-root:requirements.txt'
    );
    expect(graph.complete).toBe(false);
  });

  it('extracts exact identities from Python, Go, Rust, Java Gradle and PHP locks', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'Pipfile.lock'),
      JSON.stringify({
        _meta: {
          sources: [
            { name: 'pypi', url: 'https://pypi.org/simple', verify_ssl: true }
          ]
        },
        default: { requests: { version: '==2.31.0' } },
        develop: { pytest: { version: '==7.4.0' } }
      })
    );
    await writeFile(
      path.join(root, 'go.mod'),
      'module github.com/acme/app\n\nrequire github.com/acme/lib v1.2.3\n'
    );
    await writeFile(
      path.join(root, 'go.sum'),
      'github.com/acme/lib v1.2.3 h1:abc=\ngithub.com/acme/lib v1.2.3/go.mod h1:def=\n'
    );
    await writeFile(
      path.join(root, 'Cargo.lock'),
      'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.188"\n'
    );
    await writeFile(
      path.join(root, 'gradle.lockfile'),
      'org.example:lib:2.4.1=compileClasspath\n'
    );
    await writeFile(
      path.join(root, 'composer.lock'),
      JSON.stringify({
        packages: [
          {
            name: 'vendor/lib',
            version: 'v3.1.0',
            require: { 'vendor/helper': '^1.0' }
          },
          { name: 'vendor/helper', version: '1.2.0' }
        ]
      })
    );
    await writeFile(
      path.join(root, 'composer.json'),
      JSON.stringify({ require: { 'vendor/lib': '^3.0' } })
    );

    const items = await readOtherEcosystemInventory(root);
    expect(
      items
        .map(
          ({ ecosystem, name, version }) => `${ecosystem}:${name}@${version}`
        )
        .sort()
    ).toEqual([
      'Go:github.com/acme/lib@v1.2.3',
      'Maven:org.example:lib@2.4.1',
      'Packagist:vendor/helper@1.2.0',
      'Packagist:vendor/lib@3.1.0',
      'PyPI:pytest@7.4.0',
      'PyPI:requests@2.31.0',
      'crates.io:serde@1.0.188'
    ]);
    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');
    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(graph.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          from: 'root',
          name: 'vendor/lib',
          section: 'dependency'
        }),
        expect.objectContaining({
          name: 'vendor/helper',
          requirement: '^1.0'
        }),
        expect.objectContaining({
          from: 'root',
          name: 'github.com/acme/lib',
          section: 'dependency'
        })
      ])
    );
  });

  it('resolves Composer path workspaces and keeps dev roots distinct', async () => {
    const root = await fixture();
    await mkdir(path.join(root, 'packages/app'), { recursive: true });
    await mkdir(path.join(root, 'packages/shared'), { recursive: true });
    await mkdir(path.join(root, 'packages/branch'), { recursive: true });
    await writeFile(
      path.join(root, 'composer.json'),
      JSON.stringify({
        repositories: [{ type: 'path', url: 'packages/*' }],
        require: { 'acme/app': '^2.0', 'acme/branch': 'dev-main' },
        'require-dev': { 'phpunit/phpunit': '^10.0', php: '^8.2' }
      })
    );
    await writeFile(
      path.join(root, 'composer.lock'),
      JSON.stringify({
        packages: [{ name: 'vendor/cache', version: '1.2.0' }],
        'packages-dev': [{ name: 'phpunit/phpunit', version: '10.2.0' }]
      })
    );
    await writeFile(
      path.join(root, 'packages/app/composer.json'),
      JSON.stringify({
        name: 'acme/app',
        version: '2.1.0',
        require: { 'acme/shared': '^1.0', php: '^8.2' }
      })
    );
    await writeFile(
      path.join(root, 'packages/shared/composer.json'),
      JSON.stringify({ name: 'acme/shared', version: '1.4.0' })
    );
    await writeFile(
      path.join(root, 'packages/branch/composer.json'),
      JSON.stringify({ name: 'acme/branch', version: 'dev-main' })
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    const byName = new Map(graph.packages.map((item) => [item.name, item]));
    expect(graph.complete).toBe(false);
    expect(byName.get('acme/app')).toMatchObject({
      version: '2.1.0',
      workspace: 'packages/app',
      resolutionConfidence: 'workspace',
      direct: true,
      development: false
    });
    expect(byName.get('acme/shared')).toMatchObject({
      version: '1.4.0',
      workspace: 'packages/shared',
      resolutionConfidence: 'workspace',
      direct: false
    });
    expect(byName.get('acme/branch')).toMatchObject({
      version: 'dev-main',
      workspace: 'packages/branch',
      resolutionConfidence: 'unknown',
      direct: true
    });
    expect(byName.get('phpunit/phpunit')).toMatchObject({
      direct: true,
      development: true
    });
    expect(graph.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ from: 'root', name: 'acme/app' }),
        expect.objectContaining({ from: 'root', name: 'acme/branch' }),
        expect.objectContaining({ from: 'root', name: 'phpunit/phpunit' }),
        expect.objectContaining({ name: 'acme/shared', requirement: '^1.0' })
      ])
    );
    expect(graph.warnings).toContain(
      'composer-workspace-version-unverified:packages/branch/composer.json'
    );
    expect(graph.warnings).not.toContain(
      'ecosystem-workspace-graph-incomplete'
    );
  });

  it('does not link a Composer requirement to one incompatible locked package', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'composer.json'),
      JSON.stringify({ require: { 'vendor/library': '^2.0' } })
    );
    await writeFile(
      path.join(root, 'composer.lock'),
      JSON.stringify({
        packages: [{ name: 'vendor/library', version: '1.5.0' }]
      })
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(graph.edges.some((edge) => edge.from === 'root')).toBe(false);
    expect(graph.packages[0]).toMatchObject({
      direct: false,
      development: false
    });
    expect(graph.warnings).toContain(
      'unresolved-Packagist-root-dependency:vendor/library'
    );
  });

  it('keeps Composer branch versions unknown instead of treating them as releases', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'composer.json'),
      JSON.stringify({ require: { 'vendor/library': 'dev-main' } })
    );
    await writeFile(
      path.join(root, 'composer.lock'),
      JSON.stringify({
        packages: [{ name: 'vendor/library', version: 'dev-main' }]
      })
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(graph.packages[0]).toMatchObject({
      ecosystem: 'Packagist',
      name: 'vendor/library',
      version: 'dev-main',
      resolutionConfidence: 'unknown'
    });
    expect(graph.warnings).toContain(
      'composer-branch-version-unverified:vendor/library'
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: graph.packages[0]?.id,
        requirement: 'dev-main'
      })
    );
  });

  it('ignores Composer platform requirements and rejects external path identities', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'composer.json'),
      JSON.stringify({
        require: {
          php: '^8.2',
          'php-64bit': '*',
          'ext-json': '*',
          'composer-plugin-api': '^2.0',
          'composer-runtime-api': '^2.0'
        }
      })
    );
    await writeFile(
      path.join(root, 'composer.lock'),
      JSON.stringify({
        packages: [
          {
            name: 'vendor/local',
            version: '1.2.0',
            dist: {
              type: 'path',
              url: 'https://private.example/packages/local?token=secret'
            }
          },
          { name: '../outside', version: '1.0.0' }
        ],
        'packages-dev': []
      })
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages).toHaveLength(1);
    expect(graph.packages[0]).toMatchObject({
      name: 'vendor/local',
      resolutionConfidence: 'unknown',
      source: 'composer.lock:path-unverified',
      direct: false
    });
    expect(graph.warnings).toContain(
      'composer-lock-package-unresolved:packages'
    );
    expect(JSON.stringify(graph)).not.toMatch(/private\.example|token=secret/u);
    expect(graph.complete).toBe(false);
  });

  it('treats an empty Composer graph with only platform requirements as complete', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'composer.json'),
      JSON.stringify({
        require: {
          php: '^8.2',
          'ext-json': '*',
          'composer-runtime-api': '^2.0'
        }
      })
    );
    await writeFile(
      path.join(root, 'composer.lock'),
      JSON.stringify({ packages: [], 'packages-dev': [] })
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages).toEqual([]);
    expect(graph.edges).toEqual([]);
    expect(graph.warnings).toEqual([]);
    expect(graph.complete).toBe(true);
  });

  it('marks Composer packages from custom repositories unknown without exposing repository URLs', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'composer.json'),
      JSON.stringify({
        repositories: [
          {
            type: 'composer',
            url: 'https://private.example/registry?token=secret'
          }
        ],
        require: { 'company/internal-library': '^1.0' }
      })
    );
    await writeFile(
      path.join(root, 'composer.lock'),
      JSON.stringify({
        packages: [{ name: 'company/internal-library', version: '1.2.0' }],
        'packages-dev': []
      })
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages).toContainEqual(
      expect.objectContaining({
        name: 'company/internal-library',
        version: '1.2.0',
        direct: true,
        resolutionConfidence: 'unknown',
        source: 'composer.lock:repository-unverified'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        name: 'company/internal-library',
        requirement: '^1.0'
      })
    );
    expect(graph.warnings).toContain(
      'composer-repository-provenance-unverified'
    );
    expect(JSON.stringify(graph)).not.toMatch(/private\.example|token=secret/u);
    expect(graph.complete).toBe(false);
  });

  it('does not infer installed versions from ranges or malformed lockfiles', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'Pipfile.lock'), '{broken');
    await writeFile(path.join(root, 'requirements.txt'), 'requests>=2.0');
    const items = await readOtherEcosystemInventory(root);
    expect(items).toEqual([]);
  });

  it('keeps go.mod requirements unknown without an MVS-resolved graph', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.sum'),
      'github.com/acme/old v1.0.0 h1:abc=\n'
    );
    const orphaned = await readOtherEcosystemInventory(root);
    expect(orphaned).toEqual([]);

    await writeFile(
      path.join(root, 'go.mod'),
      [
        'module github.com/acme/app',
        'require (',
        '  github.com/acme/lib v1.2.3',
        '  github.com/acme/range latest',
        ')'
      ].join('\n')
    );
    const result = await readOtherEcosystemInventory(root);
    expect(result.map(({ name, version }) => `${name}@${version}`)).toEqual([
      'github.com/acme/lib@v1.2.3'
    ]);
    expect(result[0]?.resolutionConfidence).toBe('unknown');
    const detailed =
      await import('../../src/core/dependencies/ecosystem-inventory.js').then(
        ({ readOtherEcosystemInventoryDetailed }) =>
          readOtherEcosystemInventoryDetailed(root)
      );
    expect(detailed.complete).toBe(false);
    expect(detailed.warnings).toContain(
      'go-checksum-unavailable:github.com/acme/lib@v1.2.3'
    );
    expect(detailed.warnings).toContain('go-module-graph-not-resolved:go.mod');
  });

  it('resolves the Go MVS-selected version only after explicit tool execution consent', async () => {
    const root = await fixture();
    const goModSum = `h1:${Buffer.alloc(32, 7).toString('base64')}`;
    const replacementGoModSum = `h1:${Buffer.alloc(32, 8).toString('base64')}`;
    const metadata = {
      'go.mod': [
        'module example.test/app',
        'go 1.24.0',
        'require (',
        '  example.test/lib v1.2.0',
        '  example.test/original v1.0.0',
        ')'
      ].join('\n'),
      'go.sum': [
        `example.test/lib v1.3.0/go.mod ${goModSum}`,
        `example.test/fork v1.1.0/go.mod ${replacementGoModSum}`
      ].join('\n')
    };
    const fileSource = {
      files: Object.keys(metadata),
      hasFile: (relativePath: string) => relativePath in metadata,
      readText: (relativePath: string) =>
        metadata[relativePath as keyof typeof metadata]
    };
    const calls: string[][] = [];
    const runner = async (input: {
      cwd: string;
      args: readonly string[];
      env: NodeJS.ProcessEnv;
    }): Promise<string> => {
      calls.push([...input.args]);
      expect(input.cwd).not.toBe(root);
      expect(input.env.GOSUMDB).toBe('sum.golang.org');
      expect(input.env.GOPROXY).toBe('https://proxy.golang.org');
      expect(input.env.GOFLAGS).toBe('-mod=mod');
      expect(input.executable).toBe('injected-go-command-runner');
      if (input.args[0] === 'version') return 'go version go1.24.1 linux/amd64';
      if (input.args[0] === 'list') {
        await writeFile(
          path.join(input.cwd, 'go.sum'),
          [
            `example.test/lib v1.3.0/go.mod ${goModSum}`,
            `example.test/fork v1.1.0/go.mod ${replacementGoModSum}`
          ].join('\n')
        );
        return [
          JSON.stringify({ Path: 'example.test/app', Main: true }),
          JSON.stringify({
            Path: 'example.test/lib',
            Version: 'v1.3.0'
          }),
          JSON.stringify({
            Path: 'example.test/original',
            Version: 'v1.0.0',
            Replace: {
              Path: 'example.test/fork',
              Version: 'v1.1.0'
            }
          })
        ].join('\n');
      }
      return [
        'example.test/app go@1.24.0',
        'example.test/app example.test/lib@v1.3.0',
        'example.test/app example.test/original@v1.0.0',
        'example.test/original@v1.0.0 => example.test/fork@v1.1.0',
        'go@1.24.0 toolchain@go1.24.0'
      ].join('\n');
    };

    const withoutConsent = await readOtherEcosystemInventoryDetailed(
      root,
      fileSource
    );
    expect(calls).toHaveLength(0);
    expect(withoutConsent.packages[0]?.resolutionConfidence).toBe('unknown');

    const resolved = await readOtherEcosystemInventoryDetailed(
      root,
      fileSource,
      { allowGoToolExecution: true, goCommandRunner: runner }
    );
    expect(calls).toEqual([
      ['version'],
      ['list', '-m', '-json', 'all'],
      ['mod', 'graph']
    ]);
    expect(resolved.packages).toContainEqual(
      expect.objectContaining({
        name: 'example.test/lib',
        version: 'v1.3.0',
        resolutionConfidence: 'lockfile',
        source: 'go-tool:mvs-sumdb-verified'
      })
    );
    expect(resolved.packages).toContainEqual(
      expect.objectContaining({
        name: 'example.test/fork',
        version: 'v1.1.0',
        resolutionConfidence: 'lockfile',
        source: 'go-tool:mvs-replacement-sumdb-verified'
      })
    );
    expect(resolved.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        name: 'example.test/fork',
        requirement: 'v1.1.0'
      })
    );
    expect(resolved.warnings).not.toContain(
      'go-module-graph-not-resolved:go.mod'
    );

    metadata['go.sum'] =
      `example.test/lib v1.3.0/go.mod h1:${Buffer.alloc(32, 9).toString('base64')}\n`;
    const mismatched = await readOtherEcosystemInventoryDetailed(
      root,
      fileSource,
      { allowGoToolExecution: true, goCommandRunner: runner }
    );
    expect(
      mismatched.packages.find((item) => item.name === 'example.test/lib')
        ?.resolutionConfidence
    ).toBe('unknown');
    expect(mismatched.warnings).toContain(
      'go-checksum-source-mismatch:example.test/lib@v1.3.0'
    );
  });

  it('does not run the Go tool in offline mode even when tool execution was requested', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      'module example.test/app\nrequire example.test/lib v1.2.3\n'
    );
    let calls = 0;
    const result = await readOtherEcosystemInventoryDetailed(root, undefined, {
      allowGoToolExecution: true,
      offline: true,
      goCommandRunner: async () => {
        calls++;
        return '';
      }
    });
    expect(calls).toBe(0);
    expect(result.warnings).toContain(
      'go-tool-execution-disabled-in-offline-mode'
    );
    expect(result.packages[0]?.resolutionConfidence).toBe('unknown');
  });

  it('resolves workspace replacements with Go workspace flags and selected-version edges', async () => {
    const root = await fixture();
    const xTextSum = `h1:${Buffer.alloc(32, 4).toString('base64')}`;
    const xModSum = `h1:${Buffer.alloc(32, 5).toString('base64')}`;
    const metadata = {
      'go.work': [
        'go 1.24.0',
        'use (',
        '  ./app',
        '  ./lib',
        ')',
        'replace golang.org/x/text v0.18.0 => golang.org/x/text v0.22.0'
      ].join('\n'),
      'app/go.mod': [
        'module example.test/app',
        'go 1.24.0',
        'require golang.org/x/text v0.16.0'
      ].join('\n'),
      'lib/go.mod': [
        'module example.test/lib',
        'go 1.24.0',
        'require golang.org/x/text v0.18.0'
      ].join('\n')
    };
    const fileSource = {
      files: Object.keys(metadata),
      hasFile: (relativePath: string) => relativePath in metadata,
      readText: (relativePath: string) =>
        metadata[relativePath as keyof typeof metadata]
    };
    const calls: string[][] = [];
    const runner = async (input: {
      cwd: string;
      args: readonly string[];
      env: NodeJS.ProcessEnv;
    }): Promise<string> => {
      calls.push([...input.args]);
      expect(input.env.GOFLAGS).toBeUndefined();
      expect(input.env.GOSUMDB).toBe('sum.golang.org');
      if (input.args[0] === 'version') return 'go version go1.27.3 linux/amd64';
      if (input.args[0] === 'list') {
        await writeFile(
          path.join(input.cwd, 'go.work.sum'),
          [
            `golang.org/x/text v0.22.0/go.mod ${xTextSum}`,
            `golang.org/x/mod v0.17.0/go.mod ${xModSum}`
          ].join('\n')
        );
        return [
          JSON.stringify({ Path: 'example.test/app', Main: true }),
          JSON.stringify({ Path: 'example.test/lib', Main: true }),
          JSON.stringify({
            Path: 'golang.org/x/text',
            Version: 'v0.18.0',
            Replace: { Path: 'golang.org/x/text', Version: 'v0.22.0' }
          }),
          JSON.stringify({ Path: 'golang.org/x/mod', Version: 'v0.17.0' })
        ].join('\n');
      }
      return [
        'example.test/app golang.org/x/text@v0.16.0',
        'example.test/lib golang.org/x/text@v0.18.0',
        'go@1.24.0 toolchain@go1.24.0',
        'golang.org/x/text@v0.16.0 golang.org/x/tools@v1.0.0',
        'golang.org/x/text@v0.18.0 golang.org/x/mod@v0.17.0'
      ].join('\n');
    };

    const graph = await readOtherEcosystemInventoryDetailed(root, fileSource, {
      allowGoToolExecution: true,
      goCommandRunner: runner
    });
    const replaced = graph.packages.find(
      (item) => item.name === 'golang.org/x/text'
    );
    const xMod = graph.packages.find(
      (item) => item.name === 'golang.org/x/mod'
    );
    expect(calls).toEqual([
      ['version'],
      ['list', '-m', '-json', 'all'],
      ['mod', 'graph']
    ]);
    expect(replaced).toMatchObject({
      version: 'v0.22.0',
      resolutionConfidence: 'lockfile',
      source: 'go-tool:mvs-replacement-sumdb-verified'
    });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({ from: replaced?.id, to: xMod?.id })
    );
    expect(graph.edges.some((edge) => edge.name === 'golang.org/x/tools')).toBe(
      false
    );
    expect(graph.warnings).not.toContain(
      'go-module-graph-reference-unresolved'
    );
    expect(graph.complete).toBe(true);
  });

  it('canonicalizes exact Python pins and never promotes ranges to versions', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'requirements.txt'),
      'Django==5.0.1\nrequests>=2.0\nfoo ~= 1.4\n'
    );
    const items = await readOtherEcosystemInventory(root);
    expect(items.map(({ name, version }) => `${name}@${version}`)).toEqual([
      'django@5.0.1'
    ]);
    expect(items[0]?.resolutionConfidence).toBe('declared-pin');
    const detailed =
      await import('../../src/core/dependencies/ecosystem-inventory.js').then(
        ({ readOtherEcosystemInventoryDetailed }) =>
          readOtherEcosystemInventoryDetailed(root)
      );
    expect(detailed.complete).toBe(false);
    expect(detailed.warnings).toContain(
      'python-requirements-are-declared-pins:requirements.txt'
    );
    expect(detailed.warnings).toContain(
      'unresolved-python-requirement:requirements.txt'
    );
  });

  it('does not confuse go.mod checksums with module archive checksums', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      'module example.test/app\nrequire example.test/lib v1.2.3\n'
    );
    await writeFile(
      path.join(root, 'go.sum'),
      'example.test/lib v1.2.3/go.mod h1:YWJjZA==\n'
    );
    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');
    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(graph.packages[0]?.integrity).toBeUndefined();
    expect(graph.warnings).toContain(
      'go-checksum-unavailable:example.test/lib@v1.2.3'
    );
  });

  it('marks malformed Go checksum entries incomplete instead of silently skipping them', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      'module example.test/app\nrequire example.test/lib v1.2.3\n'
    );
    await writeFile(
      path.join(root, 'go.sum'),
      'example.test/lib v1.2.3 not-a-valid-checksum\n'
    );

    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');
    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain('go-checksum-format-invalid');
    expect(graph.warnings).toContain(
      'go-checksum-unavailable:example.test/lib@v1.2.3'
    );
  });

  it('marks replaced Go module instances unknown and rejects conflicting go.sum hashes', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      [
        'module example.test/app',
        'require example.test/lib v1.2.3',
        'replace example.test/lib v1.2.3 => example.test/fork v1.2.0'
      ].join('\n')
    );
    const hashOne = `h1:${Buffer.alloc(32, 1).toString('base64')}`;
    const hashTwo = `h1:${Buffer.alloc(32, 2).toString('base64')}`;
    await writeFile(
      path.join(root, 'go.sum'),
      `example.test/lib v1.2.3 ${hashOne}\nexample.test/lib v1.2.3 ${hashTwo}\n`
    );
    const graph = await readOtherEcosystemInventoryDetailed(root);
    const dependency = graph.packages.find(
      (item) => item.name === 'example.test/lib'
    );
    expect(dependency).toMatchObject({
      resolutionConfidence: 'unknown',
      source: 'go.mod:replacement-unverified'
    });
    expect(dependency?.integrity).toBeUndefined();
    expect(graph.warnings).toContain(
      'go-replacement-provenance-unverified:example.test/lib'
    );
    expect(graph.warnings).toContain(
      'go-checksum-conflict:example.test/lib@1.2.3'
    );
  });

  it('keeps go.work modules distinct and rejects paths escaping the project', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.work'),
      [
        'go 1.24.0',
        'use (',
        '  ./services/api',
        '  ./libs/core',
        '  ../outside',
        ')'
      ].join('\n')
    );
    await mkdir(path.join(root, 'services/api'), { recursive: true });
    await mkdir(path.join(root, 'libs/core'), { recursive: true });
    await writeFile(
      path.join(root, 'services/api/go.mod'),
      'module example.test/api\nrequire example.test/shared v1.2.3\n'
    );
    await writeFile(
      path.join(root, 'libs/core/go.mod'),
      'module example.test/core\nrequire example.test/shared v1.2.3 // indirect\n'
    );
    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');
    const result = await readOtherEcosystemInventoryDetailed(root);
    const go = result.packages.filter((item) => item.ecosystem === 'Go');
    expect(go).toHaveLength(2);
    expect(new Set(go.map((item) => item.installPath)).size).toBe(2);
    expect(go.map((item) => item.resolutionConfidence)).toEqual([
      'unknown',
      'unknown'
    ]);
    expect(result.warnings).toContain('go-workspace-path-outside-project');
    expect(result.warnings).toContain(
      'go-module-graph-not-resolved:libs/core/go.mod'
    );
    expect(result.warnings).toContain(
      'go-module-graph-not-resolved:services/api/go.mod'
    );
    expect(result.complete).toBe(false);
  });

  it('marks modules replaced by go.work as unknown, including module-specific overrides', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.work'),
      [
        'go 1.24.0',
        'use (',
        '  .',
        ')',
        'replace (',
        '  example.test/lib v1.2.3 => ../local-lib',
        ')'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'go.mod'),
      'module example.test/app\nrequire example.test/lib v1.2.3\n'
    );
    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');

    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(
      graph.packages.find((item) => item.name === 'example.test/lib')
    ).toMatchObject({
      version: 'v1.2.3',
      source: 'go.mod:replacement-unverified',
      resolutionConfidence: 'unknown'
    });
    expect(graph.warnings).toContain('go-work-replace-resolution-incomplete');
    expect(graph.warnings).toContain(
      'go-replacement-provenance-unverified:example.test/lib'
    );
    expect(graph.complete).toBe(false);
  });

  it('uses Go vendor module selection for exact installed identities and direct edges', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      [
        'module example.test/app',
        'require example.test/lib v1.2.3',
        'require example.test/transitive v0.4.0 // indirect'
      ].join('\n')
    );
    await mkdir(path.join(root, 'vendor'), { recursive: true });
    await writeFile(
      path.join(root, 'vendor', 'modules.txt'),
      [
        '# example.test/lib v1.2.3',
        '## explicit; go 1.24.0',
        'example.test/lib',
        '# example.test/transitive v0.4.0',
        'example.test/transitive/pkg',
        '# example.test/fork v2.0.0 => ../fork',
        '## explicit; go 1.24.0',
        'example.test/fork',
        '# example.test/local => ../local',
        'example.test/local'
      ].join('\n')
    );
    const { readOtherEcosystemInventoryDetailed } =
      await import('../../src/core/dependencies/ecosystem-inventory.js');
    const graph = await readOtherEcosystemInventoryDetailed(root);
    const go = graph.packages.filter((item) => item.ecosystem === 'Go');
    const direct = go.find((item) => item.name === 'example.test/lib');
    const transitive = go.find(
      (item) => item.name === 'example.test/transitive'
    );
    const replaced = go.find((item) => item.name === 'example.test/fork');
    expect(go.map((item) => item.name).sort()).toEqual([
      'example.test/fork',
      'example.test/lib',
      'example.test/transitive'
    ]);
    expect(direct).toMatchObject({
      version: 'v1.2.3',
      direct: true,
      resolutionConfidence: 'lockfile',
      source: 'vendor/modules.txt'
    });
    expect(transitive).toMatchObject({
      version: 'v0.4.0',
      direct: false,
      resolutionConfidence: 'lockfile'
    });
    expect(replaced).toMatchObject({ resolutionConfidence: 'unknown' });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: direct?.id,
        name: direct?.name
      })
    );
    expect(graph.edges.some((edge) => edge.to === transitive?.id)).toBe(false);
    expect(graph.warnings).toContain('go-vendor-transitive-edges-unresolved');
    expect(graph.warnings).toContain('go-vendor-content-integrity-unverified');
    expect(graph.complete).toBe(false);
  });

  it('rejects traversal-like Go vendor module and replacement paths', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      'module example.test/app\ngo 1.24.0\n'
    );
    await mkdir(path.join(root, 'vendor', 'example.test', 'safe', 'pkg'), {
      recursive: true
    });
    await writeFile(
      path.join(root, 'vendor', 'example.test', 'safe', 'pkg', 'pkg.go'),
      'package pkg\n'
    );
    await writeFile(
      path.join(root, 'vendor', 'modules.txt'),
      [
        '# example.test/../escape v1.2.3',
        'example.test/../escape/pkg',
        '# example.test/local/../../replacement => ../local',
        'example.test/local/../../replacement/pkg',
        '# example.test/safe v1.0.0',
        'example.test/safe/pkg'
      ].join('\n')
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(graph.packages.some((item) => item.name.includes('..'))).toBe(false);
    expect(
      graph.packages.find((item) => item.name === 'example.test/safe')
    ).toMatchObject({ version: 'v1.0.0' });
    expect(graph.warnings).toContain('go-vendor-module-path-invalid');
  });

  it('builds Go vendored transitive edges from the captured source snapshot', async () => {
    const root = await fixture();
    const files: Record<string, string> = {
      'go.mod': 'module example.test/app\ngo 1.24.0\n',
      'vendor/modules.txt': [
        '# example.test/lib v1.2.3',
        '## explicit; go 1.24.0',
        'example.test/lib/root',
        '# example.test/lib/pkg v2.0.0',
        '## explicit; go 1.24.0',
        'example.test/lib/pkg/client',
        '# example.test/transitive v0.4.0',
        'example.test/transitive/pkg'
      ].join('\n'),
      'main.go': [
        'package main',
        '// import "example.test/ignored" is only a comment',
        'import (',
        'client "example.test/lib/root"',
        'nested "example.test/lib/pkg/client"',
        ')',
        'var _ = `import "example.test/also-ignored"`'
      ].join('\n'),
      'vendor/example.test/lib/root/root.go': [
        'package root',
        'import "example.test/transitive/pkg"'
      ].join('\n'),
      'vendor/example.test/lib/pkg/client/client.go': [
        'package client',
        'import "example.test/transitive/pkg"'
      ].join('\n'),
      'vendor/example.test/transitive/pkg/transitive.go': 'package pkg\n'
    };
    const fileSource = {
      files: Object.keys(files),
      hasFile: (relativePath: string) => relativePath in files,
      readText: (relativePath: string) => files[relativePath]
    };
    const graph = await readOtherEcosystemInventoryDetailed(root, fileSource);
    const library = graph.packages.find(
      (item) => item.name === 'example.test/lib'
    );
    const nested = graph.packages.find(
      (item) => item.name === 'example.test/lib/pkg'
    );
    const transitive = graph.packages.find(
      (item) => item.name === 'example.test/transitive'
    );
    expect(library?.direct).toBe(true);
    expect(nested?.direct).toBe(true);
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: library?.id,
        name: 'example.test/lib'
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: library?.id,
        to: transitive?.id,
        name: 'example.test/transitive',
        requirement: 'v0.4.0'
      })
    );
    expect(graph.warnings).not.toContain(
      'go-vendor-transitive-edges-unresolved'
    );
    expect(graph.warnings).toContain('go-vendor-content-integrity-unverified');
    expect(graph.complete).toBe(false);
  });

  it('reconciles Go vendor selections with go.mod requirements and rejects lower versions', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      [
        'module example.test/app',
        'go 1.24.0',
        'require example.test/lib v1.2.3'
      ].join('\n')
    );
    await mkdir(path.join(root, 'vendor'), { recursive: true });
    await writeFile(
      path.join(root, 'vendor', 'modules.txt'),
      [
        '# example.test/lib v1.1.9',
        '## explicit; go 1.24.0',
        'example.test/lib/pkg'
      ].join('\n')
    );
    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(
      graph.packages.find((item) => item.name === 'example.test/lib')
    ).toMatchObject({ resolutionConfidence: 'unknown' });
    expect(graph.warnings).toContain('go-vendor-requirement-version-mismatch');
    expect(graph.complete).toBe(false);
  });

  it('accepts a higher MVS vendor version and carries the declared direct edge', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      'module example.test/app\ngo 1.24.0\nrequire example.test/lib v1.2.3\n'
    );
    await mkdir(path.join(root, 'vendor'), { recursive: true });
    await writeFile(
      path.join(root, 'vendor', 'modules.txt'),
      [
        '# example.test/lib v1.4.0',
        '## explicit; go 1.24.0',
        'example.test/lib/pkg'
      ].join('\n')
    );
    await writeFile(
      path.join(root, 'go.sum'),
      `example.test/lib v1.4.0 h1:${Buffer.alloc(32, 0x42).toString('base64')}\n`
    );
    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(
      graph.packages.find((item) => item.name === 'example.test/lib')
    ).toMatchObject({
      version: 'v1.4.0',
      direct: true,
      resolutionConfidence: 'lockfile',
      artifactIntegrityStatus: 'declared-not-verified',
      integrity: `h1:${Buffer.alloc(32, 0x42).toString('base64')}`
    });
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        name: 'example.test/lib'
      })
    );
    expect(graph.warnings).toContain('go-checksum-database-status-unverified');
  });

  it('withholds ambiguous duplicate Go vendor module versions', async () => {
    const root = await fixture();
    await mkdir(path.join(root, 'vendor'), { recursive: true });
    await writeFile(
      path.join(root, 'vendor', 'modules.txt'),
      [
        '# example.test/lib v1.2.3',
        'example.test/lib/pkg',
        '# example.test/lib v1.3.0',
        'example.test/lib/other'
      ].join('\n')
    );
    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(
      graph.packages
        .filter((item) => item.name === 'example.test/lib')
        .every((item) => item.resolutionConfidence === 'unknown')
    ).toBe(true);
    expect(graph.warnings).toContain('go-vendor-module-identity-ambiguous');
  });

  it('withholds a vendored Go version explicitly excluded by go.mod', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'go.mod'),
      [
        'module example.test/app',
        'go 1.24.0',
        'require example.test/lib v1.2.3',
        'exclude (',
        '  example.test/lib v1.2.3',
        ')'
      ].join('\n')
    );
    await mkdir(path.join(root, 'vendor'), { recursive: true });
    await writeFile(
      path.join(root, 'vendor', 'modules.txt'),
      [
        '# example.test/lib v1.2.3',
        '## explicit; go 1.24.0',
        'example.test/lib/pkg'
      ].join('\n')
    );
    const graph = await readOtherEcosystemInventoryDetailed(root);
    expect(
      graph.packages.find((item) => item.name === 'example.test/lib')
    ).toMatchObject({ resolutionConfidence: 'unknown' });
    expect(graph.warnings).toContain('go-vendor-selected-excluded-version');
  });

  it('resolves vendored Go imports separately for Linux and Windows targets', async () => {
    const root = await fixture();
    const files: Record<string, string> = {
      'go.mod': 'module example.test/app\ngo 1.24.0\n',
      'vendor/modules.txt': [
        '# example.test/lib v1.2.3',
        '## explicit; go 1.24.0',
        'example.test/lib/pkg',
        '# example.test/linuxdep v0.1.0',
        'example.test/linuxdep/pkg',
        '# example.test/windep v0.2.0',
        'example.test/windep/pkg'
      ].join('\n'),
      'main.go': 'package main\nimport "example.test/lib/pkg"\n',
      'vendor/example.test/lib/pkg/linux.go': [
        '//go:build linux',
        '',
        'package lib',
        'import "example.test/linuxdep/pkg"'
      ].join('\n'),
      'vendor/example.test/lib/pkg/windows.go': [
        '//go:build windows',
        '',
        'package lib',
        'import "example.test/windep/pkg"'
      ].join('\n'),
      'vendor/example.test/linuxdep/pkg/pkg.go': 'package pkg\n',
      'vendor/example.test/windep/pkg/pkg.go': 'package pkg\n'
    };
    const source = {
      files: Object.keys(files),
      hasFile: (file: string) => Object.hasOwn(files, file),
      readText: (file: string) => files[file]
    };
    const linux = await readOtherEcosystemInventoryDetailed(root, source, {
      goTarget: parseGoTargetProfile({
        id: 'linux-amd64',
        goos: 'linux',
        goarch: 'amd64',
        cgo: false,
        goVersion: '1.24'
      })
    });
    const linuxLibrary = linux.packages.find(
      (item) => item.name === 'example.test/lib'
    );
    const linuxDependency = linux.packages.find(
      (item) => item.name === 'example.test/linuxdep'
    );
    const windows = await readOtherEcosystemInventoryDetailed(root, source, {
      goTarget: parseGoTargetProfile({
        id: 'windows-amd64',
        goos: 'windows',
        goarch: 'amd64',
        cgo: false,
        goVersion: '1.24'
      })
    });
    const windowsLibrary = windows.packages.find(
      (item) => item.name === 'example.test/lib'
    );
    const windowsDependency = windows.packages.find(
      (item) => item.name === 'example.test/windep'
    );

    expect(linuxLibrary?.resolutionTarget).toBe('linux-amd64');
    expect(linuxDependency?.resolutionTarget).toBe('linux-amd64');
    expect(linux.edges).toContainEqual(
      expect.objectContaining({
        from: linuxLibrary?.id,
        to: linuxDependency?.id,
        resolutionTarget: 'linux-amd64'
      })
    );
    expect(
      linux.edges.some((edge) => edge.name === 'example.test/windep')
    ).toBe(false);
    expect(windows.edges).toContainEqual(
      expect.objectContaining({
        from: windowsLibrary?.id,
        to: windowsDependency?.id,
        resolutionTarget: 'windows-amd64'
      })
    );
    const unknownTarget = await readOtherEcosystemInventoryDetailed(
      root,
      source
    );
    expect(unknownTarget.warnings).toContain(
      'go-source-build-target-unresolved'
    );
    expect(
      unknownTarget.edges.some((edge) =>
        ['example.test/linuxdep', 'example.test/windep'].includes(edge.name)
      )
    ).toBe(false);
  });

  it('does not count Go test-only imports or nested files as vendored packages', async () => {
    const root = await fixture();
    const files: Record<string, string> = {
      'go.mod': 'module example.test/app\ngo 1.24.0\n',
      'vendor/modules.txt': [
        '# example.test/lib v1.2.3',
        'example.test/lib/pkg'
      ].join('\n'),
      'main_test.go': ['package app', 'import "example.test/lib/pkg"'].join(
        '\n'
      ),
      'vendor/example.test/lib/pkg/child/child.go': 'package child\n'
    };
    const source = {
      files: Object.keys(files),
      hasFile: (file: string) => Object.hasOwn(files, file),
      readText: (file: string) => files[file]
    };
    const graph = await readOtherEcosystemInventoryDetailed(root, source);
    expect(graph.warnings).toContain('go-vendor-manifest-content-mismatch');
    expect(
      graph.packages.find((item) => item.name === 'example.test/lib')
    ).toMatchObject({ direct: false });
    expect(graph.edges.some((edge) => edge.name === 'example.test/lib')).toBe(
      false
    );
  });

  it('resolves Maven dependency-tree coordinates and parent edges', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'maven-dependency-tree.txt'),
      [
        '[INFO] app:service:jar:1.0.0',
        '[INFO] +- org.example:lib:jar:2.0.0:compile',
        '[INFO] |  \\- org.example:helper:jar:3.0.0:runtime'
      ].join('\n')
    );
    const graph = await (
      await import('../../src/core/dependencies/ecosystem-inventory.js')
    ).readOtherEcosystemInventoryDetailed(root);
    expect(
      graph.packages
        .map(({ name, version, direct }) => ({ name, version, direct }))
        .sort((left, right) => left.name.localeCompare(right.name))
    ).toEqual([
      { name: 'org.example:helper', version: '3.0.0', direct: false },
      { name: 'org.example:lib', version: '2.0.0', direct: true }
    ]);
    expect(graph.edges).toHaveLength(2);
    expect(graph.edges.map(({ from, name }) => [from, name])).toContainEqual([
      'root',
      'org.example:lib'
    ]);
    expect(graph.edges.some((edge) => edge.name === 'org.example:helper')).toBe(
      true
    );
  });

  it('parses Maven classifier coordinates and pipe-free nested branches exactly', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'maven-dependency-tree.txt'),
      [
        '[INFO] app:service:pom:1.0.0',
        '[INFO] +- org.example:tests:jar:tests:1.2.3:test',
        '[INFO] |  +- org.example:runtime:jar:2.0.0:runtime',
        '[INFO] |     \\- org.example:grandchild:jar:sources:3.0.0:provided',
        '[INFO] +- org.example:optional:jar:4.0.0:compile (optional)',
        '[INFO]    \\- org.example:leaf:jar:5.0.0:compile',
        '[INFO] +- org.example:multi:jar:6.0.0:compile',
        '[INFO] |  \\- org.example:shared:jar:classes:7.0.0:compile',
        '[INFO] +- org.example:multi:zip:6.0.0:compile',
        '[INFO]    \\- org.example:shared:zip:classes:7.0.0:compile'
      ].join('\n')
    );

    const graph = await (
      await import('../../src/core/dependencies/ecosystem-inventory.js')
    ).readOtherEcosystemInventoryDetailed(root);
    const tests = graph.packages.find(
      (item) => item.name === 'org.example:tests'
    );
    const grandchild = graph.packages.find(
      (item) => item.name === 'org.example:grandchild'
    );
    const optional = graph.packages.find(
      (item) => item.name === 'org.example:optional'
    );
    const runtime = graph.packages.find(
      (item) => item.name === 'org.example:runtime'
    );
    const shared = graph.packages.filter(
      (item) => item.name === 'org.example:shared'
    );
    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain(
      'unresolved-Maven-dependency:org.example:shared:org.example:multi'
    );
    expect(tests).toMatchObject({
      version: '1.2.3',
      classifier: 'tests',
      packageType: 'jar',
      direct: true,
      development: true
    });
    expect(grandchild).toMatchObject({
      version: '3.0.0',
      classifier: 'sources',
      development: true,
      direct: false
    });
    expect(runtime).toMatchObject({ version: '2.0.0', direct: false });
    expect(shared).toHaveLength(2);
    expect(new Set(shared.map((item) => item.id)).size).toBe(2);
    expect(shared.map((item) => item.packageType).sort()).toEqual([
      'jar',
      'zip'
    ]);
    expect(optional).toMatchObject({
      version: '4.0.0',
      direct: true,
      optional: true
    });
    expect(graph.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          from: 'root',
          to: tests?.id,
          section: 'devDependency'
        }),
        expect.objectContaining({
          from: tests?.id,
          to: runtime?.id,
          section: 'dependency'
        }),
        expect.objectContaining({
          from: 'root',
          to: optional?.id,
          section: 'optionalDependency'
        })
      ])
    );
    expect(
      graph.edges.some(
        (edge) => edge.from === runtime?.id && edge.to === grandchild?.id
      )
    ).toBe(true);
  });

  it('fails incomplete on malformed Maven coordinates or ambiguous tree indentation', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'maven-dependency-tree.txt'),
      [
        '[INFO] app:service:jar:1.0.0',
        '[INFO] +- org.example:parent:jar:1.0.0:compile',
        '[INFO]   +- org.example:bad-indent:jar:2.0.0:compile',
        '[INFO] |  \\- org.example:bad-coordinate:jar:bad:3.0.0:compile:extra',
        '[INFO] |  |  \\- org.example:orphan:jar:4.0.0:compile'
      ].join('\n')
    );

    const graph = await (
      await import('../../src/core/dependencies/ecosystem-inventory.js')
    ).readOtherEcosystemInventoryDetailed(root);

    expect(graph.complete).toBe(false);
    expect(graph.warnings).toContain('maven-tree-layout-unresolved');
    expect(graph.warnings).toContain('maven-tree-coordinate-unresolved');
    expect(graph.warnings).toContain('maven-tree-parent-edge-unresolved');
    expect(graph.packages.map((item) => item.name)).toEqual([
      'org.example:parent'
    ]);
    expect(graph.edges).toHaveLength(1);
  });

  it('imports bounded multi-module Java exports with exact scoped instances and classifiers', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'pom.xml'),
      '<project><properties><revision>1.0.0</revision></properties><dependencyManagement><dependencies><dependency><groupId>org.example</groupId><artifactId>library-bom</artifactId><version>5.0.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>'
    );
    await writeFile(
      path.join(root, 'maven-dependency-tree.json'),
      JSON.stringify({
        modules: [
          {
            groupId: 'org.acme',
            artifactId: 'service-a',
            version: '1.0.0',
            children: [
              {
                groupId: 'org.example',
                artifactId: 'library',
                version: '2.4.0',
                type: 'jar',
                scope: 'compile',
                children: [
                  {
                    groupId: 'org.example',
                    artifactId: 'helper',
                    version: '3.1.0',
                    type: 'jar',
                    scope: 'runtime',
                    children: []
                  }
                ]
              },
              {
                groupId: 'org.example',
                artifactId: 'native',
                version: '1.2.0',
                type: 'jar',
                classifier: 'linux-x64',
                scope: 'runtime',
                children: []
              },
              {
                groupId: 'org.example',
                artifactId: 'unresolved',
                version: '$' + '{revision}',
                scope: 'compile',
                children: []
              }
            ]
          },
          {
            groupId: 'org.acme',
            artifactId: 'service-b',
            version: '1.0.0',
            children: [
              {
                groupId: 'org.example',
                artifactId: 'library',
                version: '2.4.0',
                type: 'jar',
                scope: 'test',
                children: []
              }
            ]
          }
        ]
      })
    );

    const graph = await (
      await import('../../src/core/dependencies/ecosystem-inventory.js')
    ).readOtherEcosystemInventoryDetailed(root);
    const libraries = graph.packages.filter(
      (item) => item.name === 'org.example:library'
    );
    expect(libraries).toHaveLength(2);
    expect(new Set(libraries.map((item) => item.workspace)).size).toBe(2);
    expect(graph.packages).toContainEqual(
      expect.objectContaining({
        name: 'org.example:native',
        version: '1.2.0',
        classifier: 'linux-x64',
        packageType: 'jar'
      })
    );
    expect(graph.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'org.example:helper',
          requirement: '3.1.0'
        })
      ])
    );
    expect(graph.warnings).toContain(
      'java-export-coordinate-unresolved:maven-dependency-tree.json'
    );
    expect(graph.packages.some((item) => item.version.includes('$'))).toBe(
      false
    );
    expect(graph.complete).toBe(false);
  });

  it('imports Gradle resolved JSON and marks declaration-only Java projects incomplete', async () => {
    const gradleRoot = await fixture();
    await writeFile(
      path.join(gradleRoot, 'build.gradle.kts'),
      'plugins { java }\n'
    );
    await writeFile(
      path.join(gradleRoot, 'gradle-dependencies.json'),
      JSON.stringify({
        modules: [
          {
            group: 'org.acme',
            module: 'service',
            version: '1.0.0',
            dependencies: [
              {
                group: 'org.example',
                module: 'library',
                version: '2.4.0',
                scope: 'runtime',
                dependencies: []
              }
            ]
          }
        ]
      })
    );
    const gradle = await (
      await import('../../src/core/dependencies/ecosystem-inventory.js')
    ).readOtherEcosystemInventoryDetailed(gradleRoot);
    expect(gradle.complete).toBe(true);
    expect(gradle.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        name: 'org.example:library',
        requirement: '2.4.0'
      })
    );

    const declarationsOnly = await fixture();
    await writeFile(
      path.join(declarationsOnly, 'pom.xml'),
      '<project><dependencies><dependency><groupId>org.example</groupId><artifactId>library</artifactId><version>$' +
        '{revision}</version></dependency></dependencies></project>'
    );
    const unresolved = await (
      await import('../../src/core/dependencies/ecosystem-inventory.js')
    ).readOtherEcosystemInventoryDetailed(declarationsOnly);
    expect(unresolved.packages).toEqual([]);
    expect(unresolved.warnings).toContain(
      'maven-resolved-graph-unavailable:pom.xml'
    );
    expect(unresolved.complete).toBe(false);
  });

  it('marks Java export graphs incomplete when a dependency scope is unknown', async () => {
    const root = await fixture();
    await writeFile(
      path.join(root, 'gradle-dependencies.json'),
      JSON.stringify({
        modules: [
          {
            group: 'org.acme',
            module: 'service',
            version: '1.0.0',
            dependencies: [
              {
                group: 'org.example',
                module: 'library',
                version: '2.4.0',
                scope: 'customProductionScope',
                dependencies: []
              }
            ]
          }
        ]
      })
    );

    const graph = await readOtherEcosystemInventoryDetailed(root);

    expect(graph.packages).toContainEqual(
      expect.objectContaining({
        name: 'org.example:library',
        version: '2.4.0',
        direct: true,
        development: false
      })
    );
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        name: 'org.example:library',
        section: 'dependency'
      })
    );
    expect(graph.warnings).toContain(
      'java-export-scope-unresolved:gradle-dependencies.json'
    );
    expect(graph.complete).toBe(false);
  });
});
