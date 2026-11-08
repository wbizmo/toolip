import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  readOtherEcosystemInventory,
  readOtherEcosystemInventoryDetailed
} from '../../src/core/dependencies/ecosystem-inventory.js';

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

describe('non-npm lockfile inventory', () => {
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

    const graph = await readOtherEcosystemInventoryDetailed(root);
    const variants = graph.packages.filter((item) => item.name === 'shared');
    expect(variants).toHaveLength(2);
    expect(new Set(variants.map((item) => item.id)).size).toBe(2);
    expect(variants.every((item) => item.source === 'uv.lock:pypi')).toBe(true);
    expect(variants.map((item) => item.resolutionContext)).toEqual(
      expect.arrayContaining([
        JSON.stringify({ markers: ["python_version < '3.12'"] }),
        JSON.stringify({ markers: ["python_version >= '3.12'"] })
      ])
    );
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
        from: 'root',
        section: 'optionalDependency',
        extras: ['accelerated']
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

    const graph = await readOtherEcosystemInventoryDetailed(root);
    const shared = graph.packages.filter((item) => item.name === 'shared-pkg');
    expect(shared).toHaveLength(2);
    expect(shared.map((item) => item.version)).toEqual(['1.0.0', '2.0.0']);
    expect(shared.map((item) => item.resolutionConfidence)).toEqual([
      'lockfile',
      'lockfile'
    ]);
    expect(new Set(shared.map((item) => item.id)).size).toBe(2);
    expect(
      shared.map((item) => JSON.parse(item.resolutionContext ?? '{}'))
    ).toEqual([
      {
        markers: ['python_version < "3.12"'],
        extras: ['fast'],
        hashes: [`sha256:${'a'.repeat(64)}`]
      },
      {
        markers: ['python_version >= "3.12"'],
        extras: ['fast'],
        hashes: [`sha256:${'b'.repeat(64)}`]
      }
    ]);
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        from: 'root',
        to: shared[0]?.id,
        marker: 'python_version < "3.12"',
        extras: ['fast']
      })
    );
    expect(graph.complete).toBe(true);
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
        'require example.test/transitive v0.4.0'
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
      'vendor/example.test/lib/pkg/client.go': [
        'package client',
        'import "example.test/transitive/pkg"'
      ].join('\n'),
      'vendor/example.test/lib/root/root.go': [
        'package root',
        'import "example.test/transitive/pkg"'
      ].join('\n'),
      'vendor/example.test/lib/pkg/client/client.go': 'package client\n',
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
});
