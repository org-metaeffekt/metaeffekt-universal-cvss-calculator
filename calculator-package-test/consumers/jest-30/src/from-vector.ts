import { fromVector } from 'ae-cvss-calculator';

export function baseOf(vector: string): number | null {
  try {
    const base = fromVector(vector)?.calculateScores().base;
    return typeof base === 'number' ? base : null;
  } catch {
    return null;
  }
}
