import { exactScore, severityLetter } from './lib/utils';

const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

const score = exactScore(vector);
const letter = severityLetter(vector);
if (score !== 9.8 || letter !== 'C') {
  throw new Error(`Expected 9.8 C, got ${score} ${letter}`);
}

console.log(`vite-5: CVSS 3.1 ${score} ${letter}`);
