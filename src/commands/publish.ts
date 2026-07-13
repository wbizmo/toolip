import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { runSecurityDoctor } from '../core/security-doctor.js';
import { renderHtmlReport } from '../core/publish/html.js';

export function registerPublishCommand(program: Command): void {
  program
    .command('publish')
    .description('Generate a static HTML security report.')
    .option('-p, --path <path>', 'Project path.', process.cwd())
    .option('-o, --output <directory>', 'Output directory.', '.toolip-report')
    .action(async (options: { path: string; output: string }) => {
      const report = await runSecurityDoctor(options.path);
      const directory = path.resolve(options.path, options.output);
      await mkdir(directory, { recursive: true });

      const html = renderHtmlReport({
        project: path.basename(path.resolve(options.path)),
        generatedAt: new Date().toISOString(),
        findings: report.findings
      });

      await writeFile(path.join(directory, 'index.html'), html, 'utf8');
      console.log(`Static report written to ${path.join(directory, 'index.html')}`);
      console.log('Deploy this directory to GitHub Pages only after reviewing it for private data.');
    });
}
