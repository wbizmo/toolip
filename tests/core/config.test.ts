import {
  mkdtemp,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadToolipConfig } from '../../src/core/config/load.js';
import { applyFindingPolicy } from '../../src/core/config/policy.js';

describe('Toolip configuration', () => {
  it('loads defaults when no file exists', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-config-')
    );

    try {
      const config =
        await loadToolipConfig(root);

      expect(config.schemaVersion).toBe('1.0');
      expect(config.history.enabled).toBe(true);
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });

  it('applies severity overrides and suppressions', async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), 'toolip-config-policy-')
    );

    try {
      await writeFile(
        path.join(root, 'toolip.config.json'),
        JSON.stringify({
          schemaVersion: '1.0',
          rules: {
            'TLP-AST-003': {
              severity: 'medium'
            }
          },
          suppressions: [
            {
              ruleId: 'TLP-TEST-001',
              reason: 'Synthetic fixture'
            }
          ]
        })
      );

      const config =
        await loadToolipConfig(root);

      const findings = applyFindingPolicy(
        [
          {
            id: '1',
            ruleId: 'TLP-AST-003',
            title: 'Exec',
            category: 'dangerous-code',
            severity: 'high',
            confidence: 'high',
            message: 'Exec',
            source: 'test'
          },
          {
            id: '2',
            ruleId: 'TLP-TEST-001',
            title: 'Fixture',
            category: 'test',
            severity: 'high',
            confidence: 'low',
            message: 'Fixture',
            source: 'test'
          }
        ],
        config
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]?.severity).toBe(
        'medium'
      );
    } finally {
      await rm(root, {
        recursive: true,
        force: true
      });
    }
  });
});
