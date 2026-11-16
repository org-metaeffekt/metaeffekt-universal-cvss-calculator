import { baseScore } from './default-import-module-cast.js';
import { scoreAdvisory } from './default-import-narrow-cast.js';
import { baseOf } from './named-import.js';

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const V30 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const V2 = 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P';
const V4 = 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H';

const results: [string, unknown, unknown][] = [
  ['module cast, 3.1', baseScore(V31), 9.8],
  ['module cast, 3.0', baseScore(V30), 9.8],
  ['module cast, 2.0', baseScore(V2), 7.5],
  ['module cast, 4.0', baseScore(V4), 5.9],
  ['narrow cast, 3.0', scoreAdvisory('v3', V30), '9.8'],
  ['narrow cast, 4.0', scoreAdvisory('v4', V4), '5.9'],
  ['named import, 3.1', baseOf('v3', V31), 9.8],
  ['named import, 2.0', baseOf('v2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P'), 7.5],
  ['named import, 4.0', baseOf('v4', V4), 5.9],
];

for (const [name, actual, expected] of results) {
  if (actual !== expected) {
    throw new Error(`${name}: expected ${expected}, got ${actual}`);
  }
}

console.log(`node-esm-bundler: ${results.length} checks passed`);
