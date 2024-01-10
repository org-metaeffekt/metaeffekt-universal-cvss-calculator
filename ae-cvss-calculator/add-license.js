// postbuild script to add license header to the bundle

const fs = require('fs');
const path = require('path');

const licensePath = path.join(__dirname, 'res/license-header.txt');
const bundlePath = path.join(__dirname, 'dist/ae-cvss-calculator.js');

console.log('Adding license header to bundle:');
console.log('  license: ' + licensePath);
console.log('  bundle:  ' + bundlePath);

if (!fs.existsSync(licensePath)) {
    throw new Error('License file not found in ' + licensePath);
}

if (!fs.existsSync(bundlePath)) {
    throw new Error('Bundle file not found in ' + bundlePath);
}

const license = fs.readFileSync(licensePath, 'utf8');
const bundle = fs.readFileSync(bundlePath, 'utf8');

fs.writeFileSync(bundlePath, license + '\n' + bundle);
