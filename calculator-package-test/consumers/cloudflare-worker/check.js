import worker from './dist/index.js'

const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
const response = await worker.fetch(new Request(`https://worker.test/?vector=${encodeURIComponent(vector)}`))
const [first] = await response.json()

if (first?.id !== 'ADVISORY-1' || first?.score !== 9.8) {
  throw new Error(`Unexpected worker response ${JSON.stringify(first)}`)
}

console.log(`cloudflare-worker: worker bundle scored ${first.score}`)
