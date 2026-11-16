import { baseOfRating, type Rating } from './handlers/vulnerabilities';

const cases: [Rating, number][] = [
  [{ version: '4.0', vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H' }, 5.9],
  [{ version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, 9.8],
  [{ version: '3.0', vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, 9.8],
  [{ version: '2.0', vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }, 7.5],
];

for (const [rating, expected] of cases) {
  const actual = baseOfRating(rating);
  if (actual !== expected) {
    throw new Error(`${rating.vector}: expected ${expected}, got ${actual}`);
  }
}

console.log('jest-29 vite build: CVSS 4.0, 3.1, 3.0 and 2.0 scored');
