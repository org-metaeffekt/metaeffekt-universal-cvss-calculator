import { Cvss3P1 } from 'ae-cvss-calculator'
import ScoreLabel from '@/components/ScoreLabel.vue'
import ScoreValue from '@/components/ScoreValue.vue'
import { categoriesOf, emptyVector, isVersion4, SEVERITY_ORDER, vectorFromText } from '@/deep-types-editor'
import { rate, versionName } from '@/deep-types-rating'
import { definedMetrics, heading } from '@/from-vector'
import { overall } from '@/namespace-import'
import { overallOrNull } from '@/overall'
import { makeScorer, unwrapVector } from '@/scorer'

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
const V30 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
const V2 = 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
const V4 = 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H'

const editorV31 = vectorFromText(V31)
const editorV4 = vectorFromText(V4)
const rating = rate(V4)

const results: [string, unknown, unknown][] = [
  ['fromVector heading', heading(V31, 'CRITICAL'), 'CVSS:3.1 CRITICAL 9.8'],
  ['fromVector metrics', definedMetrics(V31).length, 8],
  ['deep types, instanceof', editorV31 instanceof Cvss3P1, true],
  ['deep types, 3.1', editorV31?.calculateScores().overall, 9.8],
  ['deep types, 4.0', isVersion4(editorV4) ? editorV4.calculateScores().overall : null, 5.9],
  ['deep types, categories', categoriesOf(emptyVector('3.1')).some((entry) => entry.category.name === 'base'), true],
  ['deep types, severity order', SEVERITY_ORDER.CRITICAL > SEVERITY_ORDER.HIGH, true],
  ['deep types, 3.1 rating', rate(V31).scores.overall, 9.8],
  ['deep types, 4.0 rating', rating.family === 'current' ? `${rating.scores.overall} ${rating.label} ${rating.macro}` : null, '5.9 CVSS-B 211100'],
  ['deep types, fromVector name', versionName(V30), 'CVSS:3.0'],
  ['namespace import, 2.0', overall('2.0', V2), 7.5],
  ['namespace import, 4.0', overall('4.0', V4), 5.9],
  ['overall, 3.0', overallOrNull(V30), 9.8],
  ['overall, 4.0', overallOrNull(V4), 5.9],
  ['scorer, wrapped 2.0', makeScorer('2.0', unwrapVector(`(${V2})`)).calculateScores().overall, 7.5],
  ['scorer, 3.1', makeScorer('3.1', V31).calculateScores().overall, 9.8],
  ['vue components bundled', Boolean(ScoreLabel && ScoreValue), true],
]

for (const [name, actual, expected] of results) {
  if (actual !== expected) {
    throw new Error(`${name}: expected ${expected}, got ${actual}`)
  }
}

console.log(`vite-8 client build: ${results.length} checks passed`)
