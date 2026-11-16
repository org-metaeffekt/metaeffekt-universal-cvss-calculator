const { baseScores } = require('./base-scores');

const scores = baseScores({
  severity: [
    { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    { type: 'CVSS_V4', score: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H' },
  ],
});

if (scores.CVSS_V3 !== 9.8 || scores.CVSS_V4 !== 5.9) {
  throw new Error('Expected 9.8 and 5.9, got ' + JSON.stringify(scores));
}

console.log('node-cjs plain require: CVSS 3.1 ' + scores.CVSS_V3 + ', CVSS 4.0 ' + scores.CVSS_V4);
