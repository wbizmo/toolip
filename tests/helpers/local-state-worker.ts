import { writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import {
  appendHistory,
  clearHistory,
  type HistoryIntegrityOptions
} from '../../src/core/history/store.js';
import { withLocalStateLock } from '../../src/core/local-lock.js';
import { setSecret } from '../../src/core/vault.js';

const [mode, location, id, value, readyPath, staleMs] = process.argv.slice(2);

if (mode === 'vault') {
  if (!location || !id || value === undefined)
    throw new Error('Invalid worker arguments.');
  await setSecret({
    key: id,
    value,
    masterPassword: 'worker-test-password',
    vaultPath: location
  });
} else if (mode === 'history') {
  if (!location || !id) throw new Error('Invalid worker arguments.');
  await appendHistory(location, historyEntry(id));
} else if (mode === 'history-signed') {
  if (!location || !id) throw new Error('Invalid worker arguments.');
  const integrity: HistoryIntegrityOptions = {
    key: Buffer.alloc(32, 41),
    keyId: 'multiprocess-test-key'
  };
  await appendHistory(location, historyEntry(id), 500, integrity);
} else if (mode === 'history-clear') {
  if (!location) throw new Error('Invalid worker arguments.');
  await clearHistory(location);
} else if (mode === 'hold-lock') {
  if (!location || !readyPath) throw new Error('Invalid worker arguments.');
  await withLocalStateLock(
    location,
    async (assertOwned) => {
      await writeFile(readyPath, 'ready', 'utf8');
      await delay(Number(value ?? 1_000));
      await assertOwned();
    },
    5_000,
    Number(staleMs ?? 30_000)
  );
} else {
  throw new Error('Unknown local-state worker mode.');
}

function historyEntry(entryId: string) {
  return {
    id: entryId,
    createdAt: new Date(0).toISOString(),
    toolipVersion: '3.2.1',
    command: 'scan',
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0
    },
    findingIds: []
  };
}
