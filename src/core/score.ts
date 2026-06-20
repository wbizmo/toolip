import type { ToolipFinding } from './report.js';

export type ScoreGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export type ToolipScore = {
  dependencyHealth: number;
  secretHygiene: number;
  configurationSecurity: number;
  gitSafety: number;
  overall: number;
  grade: ScoreGrade;
};

export function calculateScore(input?: Partial<Omit<ToolipScore, 'overall' | 'grade'>>): ToolipScore {
  const dependencyHealth = clamp(input?.dependencyHealth ?? 100);
  const secretHygiene = clamp(input?.secretHygiene ?? 100);
  const configurationSecurity = clamp(input?.configurationSecurity ?? 100);
  const gitSafety = clamp(input?.gitSafety ?? 100);

  const overall = Math.round(
    (dependencyHealth + secretHygiene + configurationSecurity + gitSafety) / 4
  );

  return {
    dependencyHealth,
    secretHygiene,
    configurationSecurity,
    gitSafety,
    overall,
    grade: gradeScore(overall)
  };
}

export function calculateDependencyHealth(findings: ToolipFinding[]): number {
  const penalty = findings.reduce((total, finding) => {
    if (finding.severity === 'critical') return total + 35;
    if (finding.severity === 'high') return total + 25;
    if (finding.severity === 'medium') return total + 12;
    if (finding.severity === 'low') return total + 5;
    return total + 0;
  }, 0);

  return clamp(100 - penalty);
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function gradeScore(score: number): ScoreGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
