const calculator = require('ae-cvss-calculator');

function overall(vector) {
    if (vector.startsWith('CVSS:4.0/')) return new calculator.Cvss4P0(vector).calculateScores().overall;
    if (vector.startsWith('CVSS:3.0/')) return new calculator.Cvss3P0(vector).calculateScores().overall;
    return new calculator.Cvss2(vector).calculateScores().overall;
}

const actual = [
    'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H',
    'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'AV:N/AC:L/Au:N/C:P/I:P/A:P',
].map(overall).join(',');

if (actual !== '5.9,9.8,7.5') {
    throw new Error('Expected 5.9,9.8,7.5, got ' + actual);
}

console.log('node-cjs .cjs require: ' + actual);
