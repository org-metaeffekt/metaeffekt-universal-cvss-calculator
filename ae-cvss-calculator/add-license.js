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
