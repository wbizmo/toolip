import { readFile } from 'node:fs/promises';

const content = await readFile(
  'CHANGELOG.md',
  'utf8'
);

const errors = [];

if (!content.startsWith('# Changelog')) {
  errors.push(
    'CHANGELOG.md must begin with "# Changelog".'
  );
}

if (content.trim().length < 300) {
  errors.push(
    'CHANGELOG.md appears to be empty or truncated.'
  );
}

if (/(^|\n)\s*NaN\s*(\n|$)/.test(content)) {
  errors.push(
    'CHANGELOG.md contains an invalid NaN value.'
  );
}

if (!content.includes('## Unreleased')) {
  errors.push(
    'CHANGELOG.md must contain an Unreleased section.'
  );
}

if (!content.includes('## 2.0.1 - 2026-07-13')) {
  errors.push(
    'CHANGELOG.md is missing the v2.0.1 entry.'
  );
}

if (errors.length > 0) {
  console.error(
    'Changelog verification failed:'
  );

  for (const error of errors) {
    console.error(`- ${error}`);
  }

  process.exit(1);
}

console.log('Changelog verification passed.');
