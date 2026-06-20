import type { Command } from 'commander';
import chalk from 'chalk';
import { buildDependencyTree } from '../core/dependency-tree.js';

export function registerTreeCommand(program: Command): void {
  program
    .command('tree')
    .description('Display a dependency tree summary.')
    .option('-p, --path <path>', 'Project path to analyze.', process.cwd())
    .action(async (options: { path: string }) => {
      const tree = await buildDependencyTree(options.path);

      console.log(chalk.bold('Toolip Dependency Tree'));
      console.log('');
      console.log(`${chalk.dim('Direct Dependencies:')} ${tree.summary.direct}`);
      console.log(`${chalk.dim('Transitive Dependencies:')} ${tree.summary.transitive}`);
      console.log(`${chalk.dim('Max Depth:')} ${tree.summary.maxDepth}`);
      console.log('');

      for (const dependency of tree.dependencies) {
        console.log(`${chalk.green('├─')} ${dependency.name}@${dependency.version} ${chalk.dim(`(${dependency.type})`)}`);
      }
    });
}
