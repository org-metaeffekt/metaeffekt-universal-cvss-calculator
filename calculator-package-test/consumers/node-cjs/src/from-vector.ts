import { fromVector } from 'ae-cvss-calculator';

export type Level = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface VectorScore {
  vector: string;
  base: number;
  level: Level;
}

const LEVELS: [number, Level][] = [
  [9, 'critical'],
  [7, 'high'],
  [4, 'medium'],
  [0.1, 'low'],
];

export function scoreVector(vector: string): VectorScore | null {
  if (!vector.startsWith('CVSS:')) {
    return null;
  }
  try {
    const base = fromVector(vector)?.calculateScores().base;
    if (typeof base !== 'number') {
      return null;
    }
    const level = LEVELS.find(([minimum]) => base >= minimum)?.[1] ?? 'none';
    return { vector, base, level };
  } catch {
    return null;
  }
}
