import {
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateSbom } from '../../src/core/sbom/generate.js';

describe('SBOM generation', () => {
  async function fixture(): Promise<string> {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-sbom-')
    );

    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({
        name: 'fixture',
        version: '1.0.0',
        license: 'MIT',
        dependencies: {
          express: '^5.0.0'
        }
      })
    );

    await writeFile(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: {
              express: '^5.0.0'
            }
          },
          'node_modules/express': {
            version: '5.0.0',
            dependencies: {
              router: '^2.0.0'
            }
          },
          'node_modules/router': {
            version: '2.0.0'
          }
        }
      })
    );

    return root;
  }

  it('generates CycloneDX 1.5 JSON with resolved relationships', async () => {
    const root = await fixture();

    try {
      const document = await generateSbom(
        root,
        'cyclonedx'
      );

      expect(document.bomFormat).toBe(
        'CycloneDX'
      );
      expect(document.specVersion).toBe('1.5');
      expect(
        (document.components as unknown[]).length
      ).toBe(2);

      const relationships = document.dependencies as Array<{
        ref: string;
        dependsOn: string[];
      }>;
      const rootRelationship = relationships[0];
      const expressRelationship = relationships.find(
        (relationship) =>
          relationship.ref === rootRelationship?.dependsOn[0]
      );

      expect(rootRelationship?.dependsOn).toHaveLength(1);
      expect(expressRelationship?.dependsOn).toHaveLength(1);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('generates SPDX 2.3 JSON with graph relationships', async () => {
    const root = await fixture();

    try {
      const document = await generateSbom(
        root,
        'spdx'
      );

      expect(document.spdxVersion).toBe(
        'SPDX-2.3'
      );
      expect(
        (document.packages as unknown[]).length
      ).toBe(3);
      expect(
        (document.relationships as unknown[]).length
      ).toBe(2);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
