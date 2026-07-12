import {
  mkdir,
  readFile,
  rename,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import type {
  HistoryEntry,
  HistoryStore
} from './types.js';

const schemaVersion = '1.0' as const;

export function historyFilePath(root: string): string {
  return path.join(root, '.toolip', 'history.json');
}

export async function readHistory(
  root: string
): Promise<HistoryStore> {
  const filePath = historyFilePath(root);

  try {
    const raw = await readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw) as HistoryStore;

    if (
      parsed.schemaVersion !== schemaVersion ||
      !Array.isArray(parsed.entries)
    ) {
      throw new Error(
        'Unsupported Toolip history schema.'
      );
    }

    return parsed;
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      error.code === 'ENOENT'
    ) {
      return {
        schemaVersion,
        entries: []
      };
    }

    throw error;
  }
}

export async function appendHistory(
  root: string,
  entry: HistoryEntry,
  maxEntries = 500
): Promise<void> {
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);
  const temporary = `${filePath}.tmp`;

  await mkdir(directory, {
    recursive: true
  });

  const current = await readHistory(root);
  const entries = [
    ...current.entries,
    entry
  ].slice(-Math.max(1, maxEntries));

  await writeFile(
    temporary,
    `${JSON.stringify(
      {
        schemaVersion,
        entries
      } satisfies HistoryStore,
      null,
      2
    )}\n`,
    {
      encoding: 'utf8',
      mode: 0o600
    }
  );

  await rename(temporary, filePath);
}

export async function clearHistory(
  root: string
): Promise<void> {
  const filePath = historyFilePath(root);
  const directory = path.dirname(filePath);

  await mkdir(directory, {
    recursive: true
  });

  await writeFile(
    filePath,
    `${JSON.stringify(
      {
        schemaVersion,
        entries: []
      } satisfies HistoryStore,
      null,
      2
    )}\n`,
    {
      encoding: 'utf8',
      mode: 0o600
    }
  );
}
