import type { Command } from 'commander';
import { ToolipError } from '../errors/toolip-error.js';
import { readReport } from './report.js';
import {
  explainFinding, openAiAssistantProvider,
  type AiAssistantProvider
} from '../assistant/index.js';
import { serializeJsonOutputBounded } from '../core/report-writer.js';

type AiCommandOptions = {
  finding: string;
  online?: boolean;
  model?: string;
  dryRun?: boolean;
};

async function runExplain(
  reportFile: string,
  options: AiCommandOptions,
  suggestFix: boolean
): Promise<void> {
  if (suggestFix && options.dryRun !== true)
    throw new ToolipError(
      'Fix suggestions are non-executing; --dry-run is required.',
      { code: 'AI_DRY_RUN_REQUIRED', exitCode: 1 }
    );
  if (!options.finding || options.finding.length > 256)
    throw new ToolipError(
      'A bounded finding identifier is required.',
      { code: 'AI_FINDING_ID_INVALID', exitCode: 1 }
    );
  if (!options.online && options.model)
    throw new ToolipError(
      '--model requires explicit --online consent.',
      { code: 'AI_NETWORK_CONSENT_REQUIRED', exitCode: 1 }
    );
  let provider: AiAssistantProvider | undefined;
  if (options.online) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey || !options.model)
      throw new ToolipError(
        '--online requires OPENAI_API_KEY and explicit --model.',
        { code: 'AI_PROVIDER_NOT_CONFIGURED', exitCode: 1 }
      );
    provider = openAiAssistantProvider(apiKey);
  }
  const report = await readReport(reportFile);
  const finding = report.findings.find((entry) => entry.id === options.finding);
  if (!finding)
    throw new ToolipError(
      'The supplied finding ID was not present in this report.',
      { code: 'AI_FINDING_NOT_FOUND', exitCode: 1 }
    );
  const advice = await explainFinding(finding, {
    networkConsent: options.online === true,
    provider,
    model: options.model
  });
  console.log(serializeJsonOutputBounded({
    ...advice,
    operation: suggestFix ? 'suggest-fix' : 'explain',
    dryRun: true,
    modifiedFiles: 0,
    humanReviewRequired: true,
    reportAnalysisState: report.analysis?.state ?? 'unknown'
  }));
}

export function registerAiCommands(program: Command): void {
  program.command('explain <report>')
    .description('Explain one reported finding locally, with optional consented AI.')
    .requiredOption('--finding <id>', 'Exact Toolip finding ID.')
    .option('--online', 'Explicitly opt in to sending redacted finding metadata to OpenAI.')
    .option('--model <model>', 'Specific OpenAI Responses model.')
    .action((file: string, options: AiCommandOptions) =>
      runExplain(file, options, false));

  program.command('suggest-fix <report>')
    .description('Show a non-executing remediation suggestion for review.')
    .requiredOption('--finding <id>', 'Exact Toolip finding ID.')
    .requiredOption('--dry-run', 'Never modify a source file or policy.')
    .option('--online', 'Explicitly opt in to sending redacted finding metadata to OpenAI.')
    .option('--model <model>', 'Specific OpenAI Responses model.')
    .action((file: string, options: AiCommandOptions) =>
      runExplain(file, options, true));
}
