export type PackageAlternative = {
  package: string;
  alternatives: Array<{
    name: string;
    reason: string;
  }>;
};

const alternativeMap: Record<string, PackageAlternative['alternatives']> = {
  request: [
    { name: 'got', reason: 'Modern HTTP client with active maintenance and strong Node.js support.' },
    { name: 'undici', reason: 'Fast official Node.js HTTP client maintained under the Node.js project.' },
    { name: 'axios', reason: 'Popular promise-based HTTP client with broad ecosystem adoption.' }
  ],
  'node-fetch': [
    { name: 'undici', reason: 'Native fetch-compatible HTTP client for modern Node.js.' },
    { name: 'ky', reason: 'Small fetch-based client for browser and modern JavaScript workflows.' }
  ],
  moment: [
    { name: 'dayjs', reason: 'Small Moment-compatible API with lower bundle size.' },
    { name: 'date-fns', reason: 'Modular date utilities with tree-shaking support.' },
    { name: 'luxon', reason: 'Modern date-time library from the Moment maintainers.' }
  ],
  lodash: [
    { name: 'lodash-es', reason: 'ES module build with better tree-shaking.' },
    { name: 'radash', reason: 'Modern utility library with TypeScript-friendly APIs.' }
  ],
  uuid: [
    { name: 'crypto.randomUUID', reason: 'Built into modern Node.js and avoids an extra dependency where suitable.' }
  ]
};

export function findAlternatives(packageName: string): PackageAlternative {
  return {
    package: packageName,
    alternatives: alternativeMap[packageName] ?? [
      {
        name: 'No curated alternative yet',
        reason: 'Toolip does not have a curated replacement for this package yet. Inspect maintenance, license, downloads, and dependency count manually.'
      }
    ]
  };
}
