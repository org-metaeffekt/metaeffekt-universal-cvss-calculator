/*
 * Copyright 2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// postbuild script to generate ae-cvss-calculator.mjs (#20)

const fs = require('fs');
const path = require('path');

const bundlePath = path.join(__dirname, 'dist/ae-cvss-calculator.js');
const mjsBundlePath = path.join(__dirname, 'dist/ae-cvss-calculator.mjs');
const typesIndexPath = path.join(__dirname, 'dist/types/index.d.mts');

console.log('Generating .mjs exports:');
console.log('  js bundle:   ' + bundlePath);
console.log('  mjs bundle:  ' + mjsBundlePath);
console.log('  types index: ' + typesIndexPath);

if (!fs.existsSync(bundlePath)) {
    throw new Error('Bundle file not found in ' + bundlePath);
}

const exportsModules = Object.keys(require(bundlePath)).sort();

fs.writeFileSync(mjsBundlePath,
    "import pkg from './ae-cvss-calculator.js';\n" +
    "export const { " + exportsModules.join(", ") + " } = pkg;\n" +
    "export default pkg;\n");

fs.writeFileSync(typesIndexPath,
    "export * from './src/index.js';\n" +
    "import * as calculator from './src/index.js';\n" +
    "export default calculator;\n");
