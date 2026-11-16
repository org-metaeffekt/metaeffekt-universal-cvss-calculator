const calculator = require('ae-cvss-calculator');

function toJson(majorVersion, vector) {
    const VectorType = majorVersion === 4 ? calculator.Cvss4P0 : calculator.Cvss3P1;
    return new VectorType(vector).createJsonSchema();
}

module.exports = { toJson };
