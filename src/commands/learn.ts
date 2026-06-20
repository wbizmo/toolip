import type { Command } from 'commander';
import chalk from 'chalk';
import { getLearnTopic, listLearnTopics } from '../core/learn.js';
import { ToolipError } from '../errors/toolip-error.js';

export function registerLearnCommand(program: Command): void {
  program
    .command('learn [topic]')
    .description('Learn secure development concepts while using Toolip.')
    .option('--list', 'List available learning topics.')
    .action((topic: string | undefined, options: { list?: boolean }) => {
      if (options.list || !topic) {
        console.log(chalk.bold('Toolip Learning Topics'));
        console.log('');

        for (const item of listLearnTopics()) {
          console.log(`${chalk.green('✓')} ${item.id} ${chalk.dim(`— ${item.title}`)}`);
        }

        return;
      }

      const lesson = getLearnTopic(topic);

      if (!lesson) {
        throw new ToolipError(`Unknown learning topic: ${topic}`, {
          code: 'LEARN_TOPIC_NOT_FOUND',
          exitCode: 1
        });
      }

      console.log(chalk.bold(lesson.title));
      console.log('');
      console.log(lesson.explanation);
      console.log('');

      printSection('Risks', lesson.risks);
      printSection('Common Mistakes', lesson.mistakes);
      printSection('Secure Examples', lesson.secureExamples);
      printSection('Best Practices', lesson.bestPractices);
    });
}

function printSection(title: string, items: string[]): void {
  console.log(chalk.bold(title));

  for (const item of items) {
    console.log(`${chalk.green('•')} ${item}`);
  }

  console.log('');
}
