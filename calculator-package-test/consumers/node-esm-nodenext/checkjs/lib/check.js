import { rateCvss40 } from './shared/cvss4.js'

const result = rateCvss40('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H')
if (result.value !== 5.9 || result.rating !== 'MEDIUM') {
  throw new Error(`Expected 5.9 MEDIUM, got ${JSON.stringify(result)}`)
}

console.log(`node-esm-nodenext checkJs: CVSS 4.0 ${result.value} ${result.rating}`)
