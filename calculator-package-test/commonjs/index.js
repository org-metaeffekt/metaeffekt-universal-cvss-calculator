const fs = require('fs');
const path = require('path');

function runTest(name, testFn) {
    try {
        testFn();
        console.log('- Success: ' + name);
    } catch (error) {
        console.error('- Failure: ' + name);
        console.error('  Reason: ' + error.message);
        process.exit(1);
    }
}

console.log('Running integration tests');

let CvssCalculator;

runTest('module loading', () => {
    CvssCalculator = require('ae-cvss-calculator');
});

runTest('module integrity', () => {
    if (!CvssCalculator || Object.keys(CvssCalculator).length === 0) {
        throw new Error('Module export is empty. Check if webpack build is included in the package.');
    }
});

runTest('types directory presence', () => {
    const typesPath = path.join(__dirname, 'node_modules', 'ae-cvss-calculator', 'dist', 'types');
    if (!fs.existsSync(typesPath)) {
        throw new Error('Type definitions directory is missing at: ' + typesPath);
    }
});

runTest('module presence', () => {
    if (!CvssCalculator) throw new Error('Module export is null or undefined');
});

runTest('Cvss4P0 class presence', () => {
    if (typeof CvssCalculator.Cvss4P0 !== 'function') throw new Error('Cvss4P0 is not a constructor');
});

runTest('CVSS 4.0 scoring calculation', () => {
    const vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H";
    const result = new CvssCalculator.Cvss4P0(vector).calculateScores(true);
    if (result.overall !== 5.9) {
        throw new Error('Expected 5.9 but got ' + result.overall);
    }
});

console.log('Integration test successful');
console.log();
