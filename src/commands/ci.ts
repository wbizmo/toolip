import type { Command } from 'commander';
import { writeFile } from 'node:fs/promises';
import { renderGitHubPolicyWorkflow } from '../integrations/github/workflow-template.js';
import { renderGitlabSecurityPipeline } from '../integrations/gitlab/ci-template.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

export function registerCiCommand(program: Command): void {
  const ci = program.command('ci')
    .description('Generate operator-reviewed CI integration recipes.');

  ci.command('github-workflow')
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

  ci.command('gitlab-workflow')
    .description('Create a non-executing, review-only GitLab SAST pipeline with an exact OCI digest.')
    .requiredOption('--image <digest>', 'Operator-trusted immutable ghcr.io/wbizmo/toolip@sha256 digest.')
    .requiredOption('--output <file>', 'New GitLab pipeline YAML file.')
    .action(async (options: { image: string; output: string }) => {
      const result = renderGitlabSecurityPipeline(options.image);
      if (!/\.ya?ml$/u.test(options.output))
        throw new TypeError('GitLab pipeline output must have a YAML extension.');
      await writeFile(options.output, result.yaml, {
        encoding: 'utf8', flag: 'wx', mode: 0o600
      });
      console.log(serializeJsonOutputBounded({
        schema: result.schema,
        status: result.status,
        stageAApproved: result.stageAApproved,
        published: result.publishes,
        output: options.output
      }));
    });
}
