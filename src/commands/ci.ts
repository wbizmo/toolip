import type { Command } from 'commander';
import { writeFile } from 'node:fs/promises';
import { renderGitHubPolicyWorkflow } from '../integrations/github/workflow-template.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

export function registerCiCommand(program: Command): void {
  program.command('ci')
    .description('Generate operator-reviewed CI integration recipes.')
    .command('github-workflow')
    .description('Generate a read-only pinned GitHub Action recipe; does not install Stage A.')
    .requiredOption('--action-sha <sha>', 'Operator-approved immutable Toolip action revision.')
    .requiredOption('--output <file>', 'New workflow YAML output path.')
    .option('--branch <name>', 'Default branch to scan on push.', 'main')
    .option('--policy-file <file>', 'Existing versioned Toolip policy in the target project.', '.toolip/policy.yaml')
    .action(async (options: {
      actionSha: string;
      output: string;
      branch: string;
      policyFile: string;
    }) => {
      const template = renderGitHubPolicyWorkflow({
        actionSha: options.actionSha,
        branch: options.branch,
        policyFile: options.policyFile
      });
      // Never overwrite an administrator's protected workflow or publish it
      // automatically. The output is a reviewable candidate only.
      await writeFile(options.output, template.workflow, {
        encoding: 'utf8', flag: 'wx', mode: 0o600
      });
      console.log(serializeJsonOutputBounded({
        status: template.status,
        privilegedStageA: template.privilegedStageA,
        output: options.output
      }));
    });
}
