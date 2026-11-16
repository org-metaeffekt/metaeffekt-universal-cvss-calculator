import {
  Cvss2,
  Cvss3P0,
  Cvss3P1,
  Cvss4P0,
  fromVector,
} from 'ae-cvss-calculator';
import {
  MultiScoreResult,
  V4ScoreResult,
} from 'ae-cvss-calculator/dist/types/src/CvssVector';

export interface LegacyRating {
  family: 'legacy';
  scores: MultiScoreResult;
}

export interface CurrentRating {
  family: 'current';
  label: string;
  macro: string;
  scores: V4ScoreResult;
}

export function rate(vector: string): LegacyRating | CurrentRating {
  if (vector.startsWith('CVSS:4.0/')) {
    const parsed = new Cvss4P0(vector);
    return {
      family: 'current',
      label: parsed.getNomenclature(),
      macro: String(parsed.getMacroVector()),
      scores: parsed.calculateScores(true),
    };
  }
  const parsed = vector.startsWith('CVSS:3.1/')
    ? new Cvss3P1(vector)
    : vector.startsWith('CVSS:3.0/')
      ? new Cvss3P0(vector)
      : new Cvss2(vector);
  return { family: 'legacy', scores: parsed.calculateScores(true) };
}

export function versionName(vector: string): string | null {
  return fromVector(vector)?.getVectorName() ?? null;
}
