import { Cvss3P1 } from 'ae-cvss-calculator';

export type SeverityLetter = 'N' | 'L' | 'M' | 'H' | 'C';

const LETTER_THRESHOLDS: [number, SeverityLetter][] = [
  [9, 'C'],
  [7, 'H'],
  [4, 'M'],
  [0.1, 'L'],
];

export function exactScore(vector: string): number | null {
  try {
    return new Cvss3P1(vector).calculateExactOverallScore();
  } catch {
    return null;
  }
}

export function severityLetter(vector: string): SeverityLetter {
  const score = exactScore(vector);
  if (score === null) {
    return 'N';
  }
  const match = LETTER_THRESHOLDS.find(([threshold]) => score >= threshold);
  return match ? match[1] : 'N';
}
