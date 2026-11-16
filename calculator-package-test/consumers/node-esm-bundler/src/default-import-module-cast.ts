import calculator from 'ae-cvss-calculator';
import { versionOf, withoutV2Prefix } from './parse.js';

const api = calculator as unknown as typeof import('ae-cvss-calculator');

function emptyVectorFor(version: string) {
  if (version === '4.0') return new api.Cvss4P0();
  if (version === '3.1') return new api.Cvss3P1();
  if (version === '3.0') return new api.Cvss3P0();
  return new api.Cvss2();
}

export function baseScore(vector: string): number | null {
  const version = versionOf(vector);
  const target = emptyVectorFor(version);
  try {
    target.applyVector(version === '2.0' ? withoutV2Prefix(vector) : vector);
    return target.calculateScores().base ?? null;
  } catch {
    return null;
  }
}
