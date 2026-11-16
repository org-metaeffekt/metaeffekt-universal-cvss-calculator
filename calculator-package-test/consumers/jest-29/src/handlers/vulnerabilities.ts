import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator';

export interface Rating {
  version: '2.0' | '3.0' | '3.1' | '4.0';
  vector: string;
}

const FACTORIES: Record<Rating['version'], (vector: string) => Cvss2 | Cvss3P0 | Cvss3P1 | Cvss4P0> = {
  '2.0': (vector) => new Cvss2(vector),
  '3.0': (vector) => new Cvss3P0(vector),
  '3.1': (vector) => new Cvss3P1(vector),
  '4.0': (vector) => new Cvss4P0(vector),
};

export function baseOfRating(rating: Rating): number | null {
  try {
    return FACTORIES[rating.version](rating.vector).calculateScores().base ?? null;
  } catch {
    return null;
  }
}
