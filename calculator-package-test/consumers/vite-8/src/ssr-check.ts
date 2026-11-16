import { overall, type Version } from './namespace-import.ts'

const cases: [Version, string, number][] = [
  ['2.0', 'AV:N/AC:L/Au:N/C:P/I:P/A:P', 7.5],
  ['3.0', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
  ['3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
  ['4.0', 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H', 5.9],
]

for (const [version, vector, expected] of cases) {
  const actual = overall(version, vector)
  if (actual !== expected) {
    throw new Error(`${vector}: expected ${expected}, got ${actual}`)
  }
}

console.log('vite-8 SSR build: CVSS 2.0, 3.0, 3.1 and 4.0 scored')
