import ScoreBadge from './ScoreBadge.vue'

const instance = { summary: null }
const summary = ScoreBadge.methods.score.call(
  instance,
  'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H'
)

if (summary.baseScore !== 5.9 || summary.baseSeverity !== 'MEDIUM') {
  throw new Error(`Expected 5.9 MEDIUM, got ${JSON.stringify(summary)}`)
}

console.log(`webpack-5 vue-loader named import: ${summary.baseScore} ${summary.baseSeverity}`)
