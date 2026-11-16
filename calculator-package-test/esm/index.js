import fs from 'fs';
import path from 'path';
import {fileURLToPath} from 'url';

const dirname = path.dirname(fileURLToPath(import.meta.url));

async function runTest(name, testFn) {
    try {
        await testFn();
        console.log('- Success: ' + name);
    } catch (error) {
        console.error('- Failure: ' + name);
        console.error('  Reason: ' + error.message);
        process.exit(1);
    }
}

console.log('Running ES module integration tests');

const expectedExports = [
    'CvssVector',
    'Cvss2',
    'Cvss3P0',
    'Cvss3P1',
    'Cvss4P0',
    'fromVector',
    'applyVectorPartsIfMetricsLower',
    'applyVectorPartsIfMetricsHigher',
    'Cvss2Components',
    'Cvss3P0Components',
    'Cvss3P1Components',
    'Cvss4P0Components',
];

let CvssCalculator;

await runTest('module loading', async () => {
    CvssCalculator = await import('ae-cvss-calculator');
});

await runTest('named exports presence', () => {
    const missing = expectedExports.filter(name => !(name in CvssCalculator));
    if (missing.length > 0) {
        throw new Error('Named exports missing: ' + missing.join(', ') + '. Found: ' + Object.keys(CvssCalculator).join(', '));
    }
});

await runTest('types directory presence', () => {
    const typesPath = path.join(dirname, 'node_modules', 'ae-cvss-calculator', 'dist', 'types');
    if (!fs.existsSync(typesPath)) {
        throw new Error('Type definitions directory is missing at: ' + typesPath);
    }
});

await runTest('Cvss4P0 class presence', () => {
    if (typeof CvssCalculator.Cvss4P0 !== 'function') throw new Error('Cvss4P0 is not a constructor');
});

await runTest('CVSS 4.0 scoring calculation', () => {
    const vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H";
    const result = new CvssCalculator.Cvss4P0(vector).calculateScores(true);
    if (result.overall !== 5.9) {
        throw new Error('Expected 5.9 but got ' + result.overall);
    }
});

await runTest('fromVector helper', () => {
    const result = CvssCalculator.fromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.calculateScores();
    if (result?.overall !== 9.8) {
        throw new Error('Expected 9.8 but got ' + result?.overall);
    }
});

await runTest('Cvss4P0Components applied to a vector', () => {
    const {Cvss4P0, Cvss4P0Components} = CvssCalculator;
    const cvss = new Cvss4P0("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N");
    cvss.applyComponent(Cvss4P0Components.AC, Cvss4P0Components.AC_VALUES.H);
    const expected = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N";
    if (cvss.toString() !== expected) {
        throw new Error('Expected ' + expected + ' but got ' + cvss.toString());
    }
});

console.log('ES module integration test successful');
console.log();
