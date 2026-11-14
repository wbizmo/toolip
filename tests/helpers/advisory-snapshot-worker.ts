import { access, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { AdvisorySnapshotCache } from '../../src/providers/intelligence/snapshot-cache.js';

const [file, recordKey, readyFile, startFile] = process.argv.slice(2);
if (!file || !recordKey || !readyFile || !startFile)
  throw new Error('Invalid advisory snapshot worker arguments.');

const cache = await AdvisorySnapshotCache.open(file);
await cache.set(recordKey, { writer: recordKey });
await writeFile(readyFile, 'ready', 'utf8');
const deadline = Date.now() + 30_000;
while (true) {
  try {
    await access(startFile);
    break;
  } catch {
    if (Date.now() > deadline)
      throw new Error('Timed out waiting for the snapshot worker barrier.');
    await delay(10);
  }
}
await cache.flush();
