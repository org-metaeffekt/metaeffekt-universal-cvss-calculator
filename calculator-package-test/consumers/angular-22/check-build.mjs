import fs from 'node:fs'
import path from 'node:path'

const browserDir = path.join('dist', 'browser')
const mainFile = fs.readdirSync(browserDir).find((file) => /^main.*\.js$/.test(file))
if (!mainFile) {
  throw new Error(`No main bundle in ${browserDir}`)
}

const bundle = fs.readFileSync(path.join(browserDir, mainFile), 'utf8')
if (!bundle.includes('calculateScores')) {
  throw new Error(`${mainFile} does not contain the calculator`)
}

console.log(`angular-22: ng build passed, ${mainFile} contains the calculator`)
