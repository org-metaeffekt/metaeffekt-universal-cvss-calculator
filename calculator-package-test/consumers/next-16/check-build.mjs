import fs from 'node:fs'

const html = fs.readFileSync('.next/server/app/index.html', 'utf8')

for (const expected of ['server-score:9.8', 'client-score:5.9']) {
  if (!html.includes(expected)) {
    throw new Error(`Prerendered page does not contain "${expected}"`)
  }
}

console.log('next-16: server component 9.8, client component 5.9')
