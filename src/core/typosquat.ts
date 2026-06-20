export type TyposquatResult = {
  input: string;
  suspected: boolean;
  suggestions: string[];
};

const popularPackages = [
  'express',
  'fastify',
  'react',
  'vue',
  'axios',
  'got',
  'lodash',
  'typescript',
  'commander',
  'chalk',
  'zod',
  'prisma',
  'vite',
  'next',
  'nestjs'
];

export function detectTyposquat(input: string): TyposquatResult {
  const normalized = input.trim().toLowerCase();

  const suggestions = popularPackages
    .map((candidate) => ({
      candidate,
      distance: levenshtein(normalized, candidate)
    }))
    .filter((item) => item.distance > 0 && item.distance <= 2)
    .sort((a, b) => a.distance - b.distance)
    .map((item) => item.candidate);

  return {
    input,
    suspected: suggestions.length > 0,
    suggestions
  };
}

function levenshtein(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, (_, row) =>
    Array.from({ length: b.length + 1 }, (_, col) => {
      if (row === 0) return col;
      if (col === 0) return row;
      return 0;
    })
  );

  for (let row = 1; row <= a.length; row += 1) {
    for (let col = 1; col <= b.length; col += 1) {
      const cost = a[row - 1] === b[col - 1] ? 0 : 1;

      matrix[row][col] = Math.min(
        matrix[row - 1][col] + 1,
        matrix[row][col - 1] + 1,
        matrix[row - 1][col - 1] + cost
      );
    }
  }

  return matrix[a.length][b.length];
}
