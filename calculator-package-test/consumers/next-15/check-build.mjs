import fs from 'node:fs'

const html = fs.readFileSync('.next/server/app/index.html', 'utf8')
const expected = 'scores:5.9,9.8,9.8,7.5'

if (!html.includes(expected)) {
  throw new Error(`Prerendered page does not contain "${expected}"`)
}

console.log('next-15: client component scored CVSS 4.0, 3.1, 3.0 and 2.0')
