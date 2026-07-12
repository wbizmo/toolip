import { mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { runSecurityDoctor } from '../security-doctor.js';

const execFileAsync = promisify(execFile);

export async function auditRemoteRepository(url: string): Promise<{
  repository: string;
  report: Awaited<ReturnType<typeof runSecurityDoctor>>;
}> {
  if (!/^https:\/\/github\.com\/[^/]+\/[^/]+(?:\.git)?$/.test(url)) {
    throw new Error('Only public GitHub repository URLs are supported.');
  }

  const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), 'toolip-remote-audit-'));
  const target = path.join(temporaryRoot, 'repository');

  try {
    await execFileAsync('gh', ['repo', 'clone', url, target, '--', '--depth=1'], {
      encoding: 'utf8'
    });

    const report = await runSecurityDoctor(target);

    return {
      repository: url,
      report
    };
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}
