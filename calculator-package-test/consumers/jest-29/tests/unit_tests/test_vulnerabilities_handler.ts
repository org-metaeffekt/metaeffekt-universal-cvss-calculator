jest.mock('ae-cvss-calculator', () => {
  const fake = (base: number) =>
    jest.fn().mockImplementation((vector: string) => ({
      calculateScores: () => {
        if (vector === 'broken') {
          throw new Error('broken vector');
        }
        return { base, overall: base };
      },
    }));
  return { Cvss2: fake(2), Cvss3P0: fake(3), Cvss3P1: fake(3.1), Cvss4P0: fake(4) };
});

import { baseOfRating } from '../../src/handlers/vulnerabilities';

describe('baseOfRating with a mocked calculator', () => {
  test('uses the class that matches the version', () => {
    expect(baseOfRating({ version: '4.0', vector: 'any' })).toBe(4);
    expect(baseOfRating({ version: '2.0', vector: 'any' })).toBe(2);
  });

  test('returns null when the class throws', () => {
    expect(baseOfRating({ version: '3.1', vector: 'broken' })).toBeNull();
  });

  test('a class on the mocked module can be swapped through require', () => {
    const mocked = require('ae-cvss-calculator');
    const original = mocked.Cvss3P0;
    mocked.Cvss3P0 = jest.fn().mockImplementation(() => ({ calculateScores: () => ({ base: 0.5 }) }));
    expect(baseOfRating({ version: '3.0', vector: 'any' })).toBe(0.5);
    mocked.Cvss3P0 = original;
  });
});
