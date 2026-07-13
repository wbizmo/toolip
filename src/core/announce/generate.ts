export type AnnouncementInput = {
  version?: string;
  fixed: number;
  added: number;
  removed: number;
  scoreBefore?: number;
  scoreAfter?: number;
};

export function generateAnnouncement(input: AnnouncementInput): string {
  const title = input.version
    ? `Toolip ${input.version} security update`
    : 'Toolip security update';

  const lines = [
    title,
    '',
    `Fixed findings: ${input.fixed}`,
    `New findings: ${input.added}`,
    `Removed findings: ${input.removed}`
  ];

  if (
    input.scoreBefore !== undefined &&
    input.scoreAfter !== undefined
  ) {
    lines.push(
      `Security score: ${input.scoreBefore} → ${input.scoreAfter}`
    );
  }

  lines.push(
    '',
    'This summary was generated locally from structured Toolip scan differences.'
  );

  return lines.join('\n');
}
