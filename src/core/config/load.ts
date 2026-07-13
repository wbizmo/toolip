import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  toolipConfigSchema,
  type ToolipConfig
} from './schema.js';

export const TOOLIP_CONFIG_FILE =
  'toolip.config.json';

export async function loadToolipConfig(
  root: string
): Promise<ToolipConfig> {
  const filePath = path.join(
    root,
    TOOLIP_CONFIG_FILE
  );

  try {
    const raw = await readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw) as unknown;

    return toolipConfigSchema.parse(parsed);
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      error.code === 'ENOENT'
    ) {
      return toolipConfigSchema.parse({});
    }

    throw error;
  }
}
