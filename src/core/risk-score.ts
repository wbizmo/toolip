export function calculateRiskScore(input: {
  deprecated: boolean;
  maintainers: number;
  ageInDays: number | null;
}): number {
  let score = 0;

  if (input.deprecated) score += 40;

  if (input.maintainers === 0) score += 30;
  else if (input.maintainers === 1) score += 15;

  if (input.ageInDays !== null && input.ageInDays > 730) {
    score += 20;
  }

  return Math.min(score, 100);
}
