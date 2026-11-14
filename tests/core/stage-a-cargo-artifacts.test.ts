import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import {
  inspectCargoArtifacts,
  inspectCargoCrateTarball,
  inspectDependencyChanges,
  parseCargoLockArtifactInventory,
  verifyCargoArtifactPolicy
} from '../../scripts/stage-a-gate.mjs';

const roots: string[] = [];
const crateName = 'safe-crate';
const crateVersion = '1.2.3';
const registrySource = 'registry+https://github.com/rust-lang/crates.io-index';

function tarGzip(
  entries: Array<{ name: string; text: string; type?: string }>
): Buffer {
  const blocks: Buffer[] = [];
  for (const entry of entries) {
    const content = Buffer.from(entry.text);
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'utf8');
    header.write('0000644\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii');
    header.write('0000000\0', 116, 8, 'ascii');
    header.write(
      `${content.length.toString(8).padStart(11, '0')}\0`,
      124,
      12,
      'ascii'
    );
    header.write('00000000000\0', 136, 12, 'ascii');
    header.fill(32, 148, 156);
    header[156] = (entry.type ?? '0').charCodeAt(0);
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const checksum = header.reduce((total, byte) => total + byte, 0);
    header.write(
      `${checksum.toString(8).padStart(6, '0')}\0 `,
      148,
      8,
      'ascii'
    );
    blocks.push(header);
    const padded = Buffer.alloc(Math.ceil(content.length / 512) * 512);
    content.copy(padded);
    blocks.push(padded);
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

function crateArchive(
  entries: Array<{ path: string; text: string; type?: string }> = [
    {
      path: 'Cargo.toml',
      text: `[package]\nname = "${crateName}"\nversion = "${crateVersion}"\nedition = "2021"\n`
    },
    { path: 'src/lib.rs', text: 'pub fn safe() -> bool { true }\n' }
  ]
): Buffer {
  const root = `${crateName}-${crateVersion}`;
  return tarGzip(
    entries.map(({ path: relativePath, text, type }) => ({
      name: `${root}/${relativePath}`,
      text,
      ...(type ? { type } : {})
    }))
  );
}

function cargoLock(checksum: string, extra = ''): string {
  return `version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "${crateName}"\nversion = "${crateVersion}"\nsource = "${registrySource}"\nchecksum = "${checksum}"\n${extra}`;
}

async function repository(files: Record<string, string>): Promise<{
  root: string;
  sha: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-stage-a-cargo-'));
  roots.push(root);
  execFileSync('git', ['init', '-q', root]);
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(root, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content);
  }
  execFileSync(
    'git',
    [
      '-C',
      root,
      '-c',
      'core.hooksPath=/dev/null',
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'add',
      '--all'
    ],
    { stdio: 'ignore' }
  );
  execFileSync(
    'git',
    [
      '-C',
      root,
      '-c',
      'core.hooksPath=/dev/null',
      '-c',
      'user.name=Toolip Test',
      '-c',
      'user.email=test@example.invalid',
      'commit',
      '-qm',
      'cargo stage-a fixture'
    ],
    { stdio: 'ignore' }
  );
  const sha = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
    encoding: 'utf8'
  }).trim();
  return { root, sha };
}

afterEach(async () =>
  Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  )
);

describe('Stage A Cargo archive verification', () => {
  it('binds registry artifacts to the exact official lock source and checksum', () => {
    const archive = crateArchive();
    const checksum = createHash('sha256').update(archive).digest('hex');
    const inventory = parseCargoLockArtifactInventory(cargoLock(checksum), {
      rootPackage: { name: 'app', version: '0.1.0' }
    });

    expect(inventory.reasons).toEqual([]);
    expect(inventory.artifactRecords).toEqual([
      expect.objectContaining({
        name: crateName,
        version: crateVersion,
        checksum,
        location: expect.stringMatching(/^cargo-lock\//u)
      })
    ]);
    expect(
      parseCargoLockArtifactInventory(
        cargoLock(checksum).replace(
          'registry+https://github.com/rust-lang/crates.io-index',
          'registry+https://attacker.invalid/index'
        ),
        { rootPackage: { name: 'app', version: '0.1.0' } }
      ).reasons
    ).toContain('cargo-source-unverified:Cargo.lock');
    expect(
      parseCargoLockArtifactInventory(
        cargoLock(checksum).replace(`checksum = "${checksum}"\n`, ''),
        { rootPackage: { name: 'app', version: '0.1.0' } }
      ).reasons
    ).toContain('cargo-checksum-missing-or-invalid:Cargo.lock');
  });

  it('requires an exact protected Cargo digest policy for every resolved crate', () => {
    const checksum = 'a'.repeat(64);
    const artifacts = [{ name: crateName, version: crateVersion, checksum }];
    expect(verifyCargoArtifactPolicy(artifacts, undefined).reasons).toContain(
      'cargo-artifact-policy-unavailable-or-invalid'
    );
    const valid = verifyCargoArtifactPolicy(
      artifacts,
      JSON.stringify({
        version: 1,
        packages: { [`${crateName}@${crateVersion}`]: checksum }
      })
    );
    expect(valid.reasons).toEqual([]);
    expect(valid.policySha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(
      verifyCargoArtifactPolicy(
        artifacts,
        JSON.stringify({
          version: 1,
          packages: { [`${crateName}@${crateVersion}`]: 'b'.repeat(64) }
        })
      ).reasons
    ).toContain(
      `cargo-artifact-policy-digest-mismatch:${crateName}@${crateVersion}`
    );
  });

  it('inspects the checked archive without extraction and retains its digest', async () => {
    const archive = crateArchive();
    const checksum = createHash('sha256').update(archive).digest('hex');
    const location = `cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3#${checksum}`;
    let requests = 0;
    const result = await inspectCargoArtifacts(
      [
        {
          location,
          name: crateName,
          version: crateVersion,
          checksum,
          source: registrySource
        }
      ],
      {
        fetchImpl: async (url, init) => {
          requests++;
          expect(url.href).toBe(
            'https://static.crates.io/crates/safe-crate/safe-crate-1.2.3.crate'
          );
          expect(init?.redirect).toBe('manual');
          return new Response(archive, { status: 200 });
        }
      }
    );

    expect(requests).toBe(1);
    expect(result.coverage).toMatchObject({
      checked: 1,
      files: 2,
      binaryFiles: 0
    });
    expect(result.reasons).toEqual([]);
    expect(result.findings).toEqual([]);
    expect(result.verifiedArtifactSha256ByLocation).toEqual({
      [location]: checksum
    });
  });

  it('fails closed on checksum mismatch, off-registry responses and archive traversal', async () => {
    const archive = crateArchive();
    const validChecksum = createHash('sha256').update(archive).digest('hex');
    const artifact = {
      location: `cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3#${'0'.repeat(64)}`,
      name: crateName,
      version: crateVersion,
      checksum: '0'.repeat(64),
      source: registrySource
    };
    const mismatch = await inspectCargoArtifacts([artifact], {
      fetchImpl: async () => new Response(archive, { status: 200 })
    });
    expect(mismatch.reasons).toContain(
      `cargo-artifact-integrity-mismatch:${artifact.location}`
    );
    expect(mismatch.verifiedArtifactSha256ByLocation).toEqual({});

    const redirected = await inspectCargoArtifacts(
      [
        {
          ...artifact,
          checksum: validChecksum,
          location: `cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3#${validChecksum}`
        }
      ],
      {
        fetchImpl: async () => {
          const response = new Response(archive, { status: 200 });
          Object.defineProperty(response, 'url', {
            value: 'https://evil.invalid/crate.crate'
          });
          return response;
        }
      }
    );
    expect(redirected.reasons).toContain(
      `cargo-artifact-redirected-outside-registry:cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3#${validChecksum}`
    );

    const traversal = inspectCargoCrateTarball(
      crateArchive([{ path: '../outside.rs', text: 'unsafe {}' }]),
      { ...artifact, checksum: validChecksum }
    );
    expect(traversal.reasons).toContain('tar-path-invalid');
  });

  it('flags build scripts and rejects symlink entries without running crate code', async () => {
    const scratch = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-cargo-sentinel-')
    );
    roots.push(scratch);
    const marker = path.join(scratch, 'build-script-ran');
    const archive = crateArchive([
      {
        path: 'Cargo.toml',
        text: `[package]\nname = "${crateName}"\nversion = "${crateVersion}"\nbuild = "build.rs"\n`
      },
      {
        path: 'build.rs',
        text: `fn main() { std::fs::write("${marker}", "ran").unwrap(); }`
      },
      { path: 'src/lib.rs', text: 'pub fn safe() {}' }
    ]);
    const inspected = inspectCargoCrateTarball(archive, {
      location: 'cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3',
      name: crateName,
      version: crateVersion
    });
    expect(inspected.hasBuildScript).toBe(true);
    expect(inspected.reasons).toContain(
      'cargo-build-script-review:cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3'
    );
    await expect(access(marker)).rejects.toThrow();

    const symlink = inspectCargoCrateTarball(
      crateArchive([{ path: 'src/link.rs', text: '../outside.rs', type: '2' }]),
      {
        location: 'cargo-lock/Q2FyZ28ubG9jaw/safe-crate@1.2.3',
        name: crateName,
        version: crateVersion
      }
    );
    expect(symlink.reasons).toContain('cargo-tar-entry-type-unsupported');
  });

  it('reads Cargo.lock from immutable Git blobs and leaves unsupported inputs incomplete', async () => {
    const archive = crateArchive();
    const checksum = createHash('sha256').update(archive).digest('hex');
    const fixture = await repository({
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n',
      'Cargo.lock': cargoLock(checksum)
    });
    const inspection = inspectDependencyChanges(
      fixture.root,
      fixture.sha,
      fixture.sha
    );
    expect(inspection.reasons).not.toContain(
      'unsupported-dependency-ecosystem-provenance'
    );
    expect(inspection.cargoArtifactRecords).toHaveLength(1);

    const unsupported = await repository({
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n',
      'Cargo.lock': cargoLock(checksum),
      'go.mod': 'module example.invalid/app\n'
    });
    expect(
      inspectDependencyChanges(
        unsupported.root,
        unsupported.sha,
        unsupported.sha
      ).reasons
    ).toContain('unsupported-dependency-ecosystem-provenance');
  });

  it('binds workspace-local lock identities to exact tracked member manifests', async () => {
    const archive = crateArchive();
    const checksum = createHash('sha256').update(archive).digest('hex');
    const workspace = await repository({
      'Cargo.toml':
        '[workspace]\nmembers = ["crates/member"]\n[workspace.package]\nversion = "0.1.0"\n',
      'crates/member/Cargo.toml':
        '[package]\nname = "member"\nversion.workspace = true\n',
      'Cargo.lock': `version = 3\n\n[[package]]\nname = "member"\nversion = "0.1.0"\n\n[[package]]\nname = "${crateName}"\nversion = "${crateVersion}"\nsource = "${registrySource}"\nchecksum = "${checksum}"\n`
    });
    const result = inspectDependencyChanges(
      workspace.root,
      workspace.sha,
      workspace.sha
    );
    expect(result.reasons).not.toContain(
      'cargo-local-package-unverified:Cargo.lock'
    );
    expect(result.reasons).not.toContain(
      'cargo-lockfile-missing:crates/member/Cargo.toml'
    );
    expect(result.cargoArtifactRecords).toHaveLength(1);

    const globWorkspace = await repository({
      'Cargo.toml': '[workspace]\nmembers = ["crates/*"]\n',
      'crates/member/Cargo.toml':
        '[package]\nname = "member"\nversion = "0.1.0"\n',
      'Cargo.lock': `version = 3\n[[package]]\nname = "member"\nversion = "0.1.0"\n`
    });
    expect(
      inspectDependencyChanges(
        globWorkspace.root,
        globWorkspace.sha,
        globWorkspace.sha
      ).reasons
    ).toContain('cargo-workspace-pattern-unverified:Cargo.toml');
  });
});
