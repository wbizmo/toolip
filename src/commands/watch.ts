import type { Command } from 'commander';
import { runSecurityDoctor } from '../core/security-doctor.js';
import { watchProject } from '../core/watch/watch.js';

export function registerWatchCommand(program: Command): void {
  program
    .command('watch')
    .description('Continuously rerun Toolip security checks as files change.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option('--once', 'Run once without watching.')
    .action(async (options: { path: string; once?: boolean }) => {
      const render = async (): Promise<void> => {
        const result = await runSecurityDoctor(options.path);
        console.clear();
        console.log('Toolip Watch');
        console.log('');
        console.log(`Updated: ${new Date().toISOString()}`);
        console.log(`Critical/secrets: ${result.summary.secrets}`);
        console.log(`Dangerous code: ${result.summary.dangerousCode}`);
        console.log(`Configuration: ${result.summary.configuration}`);
        console.log(`Total findings: ${result.findings.length}`);
      };

      await render();

      if (options.once) return;

      console.log('');
      console.log('Watching for changes. Press Ctrl+C to stop.');

      const close = watchProject(options.path, render, {
        onError(error) {
          const message = error instanceof Error ? error.message : String(error);
          console.error(`Toolip watch check failed: ${message}`);
          console.error('Watching continues; fix the error or press Ctrl+C to stop.');
        }
      });

      await new Promise<void>((resolve) => {
        const stop = (): void => {
          close();
          process.off('SIGINT', stop);
          process.off('SIGTERM', stop);
          resolve();
        };

        process.once('SIGINT', stop);
        process.once('SIGTERM', stop);
      });
    });
}
