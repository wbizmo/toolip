import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { TextFileReader } from '../text-file-reader.js';
import { toolipConfigSchema, type ToolipConfig } from './schema.js';

export const TOOLIP_CONFIG_FILE = 'toolip.config.json';
const maximumConfigBytes = 1024 * 1024;

export async function loadToolipConfig(root: string): Promise<ToolipConfig> {
  const filePath = path.join(root, TOOLIP_CONFIG_FILE);

  try {
    await lstat(filePath);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      return toolipConfigSchema.parse({});
    }
    throw error;
  }

  const read = await new TextFileReader(
    {
      maxFiles: 1,
      maxFileBytes: maximumConfigBytes,
      maxTotalBytes: maximumConfigBytes
    },
    { root }
  ).read(filePath);
  if (read.status !== 'ok')
    throw new Error(`Toolip configuration could not be read (${read.status}).`);
  const parsed = JSON.parse(read.content) as unknown;

  return toolipConfigSchema.parse(parsed);
}
