import { Cvss2, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator';

const FACTORIES = {
  v2: (vector: string) => new Cvss2(vector),
  v3: (vector: string) => new Cvss3P1(vector),
  v4: (vector: string) => new Cvss4P0(vector),
};

export type Generation = keyof typeof FACTORIES;

export function baseOf(generation: Generation, vector: string): number | undefined {
  return FACTORIES[generation](vector).calculateScores().base;
}
