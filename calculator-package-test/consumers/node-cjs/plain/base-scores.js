const { Cvss3P1, Cvss4P0 } = require('ae-cvss-calculator');

const TYPES = { CVSS_V3: Cvss3P1, CVSS_V4: Cvss4P0 };

function baseScores(record) {
  const scores = {};
  for (const { type, score } of record.severity || []) {
    const VectorType = TYPES[type];
    if (!VectorType || type in scores) {
      continue;
    }
    try {
      scores[type] = new VectorType(score).calculateScores().base;
    } catch {
      scores[type] = null;
    }
  }
  return scores;
}

module.exports = { baseScores };
