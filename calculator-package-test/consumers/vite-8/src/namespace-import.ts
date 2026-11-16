import * as calculator from 'ae-cvss-calculator';

export type Version = '2.0' | '3.0' | '3.1' | '4.0';

const withDefault = calculator as typeof calculator & { default?: typeof calculator };
const api = withDefault.default ?? calculator;

export function overall(version: Version, vector: string): number {
  switch (version) {
    case '2.0':
      return new api.Cvss2(vector).calculateScores().overall;
    case '3.0':
      return new api.Cvss3P0(vector).calculateScores().overall;
    case '3.1':
      return new api.Cvss3P1(vector).calculateScores().overall;
    case '4.0':
      return new api.Cvss4P0(vector).calculateScores().overall;
  }
}
