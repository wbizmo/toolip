import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { ToolipError } from '../errors/toolip-error.js';

export async function readSecretInputs(labels: string[]): Promise<string[]> {
  if (labels.length === 0) return [];

  if (!process.stdin.isTTY) {
    let input = '';
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) input += chunk;
    const values = input.replace(/\r/g, '').split('\n');
    if (values.length > 0 && values[values.length - 1] === '') values.pop();
    if (values.length < labels.length) {
      throw new ToolipError(`Expected ${labels.length} secret value(s) on stdin, one per line.`, {
        code: 'SECRET_INPUT_MISSING',
        exitCode: 2
      });
    }
    return values.slice(0, labels.length);
  }

  const values: string[] = [];
  for (const label of labels) {
    process.stderr.write(`${label}: `);
    const sink = new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      }
    });
    const rl = createInterface({ input: process.stdin, output: sink, terminal: true });
    try {
      values.push(await rl.question(''));
    } finally {
      rl.close();
      process.stderr.write('\n');
    }
  }
  return values;
}
