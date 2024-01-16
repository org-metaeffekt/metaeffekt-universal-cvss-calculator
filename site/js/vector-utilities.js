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
function extractVectorsFromFreeText(inputString) {
    const regex = /((?:CVSS:\d+\.\d+\/)?(?:[a-zA-Z]{1,3}:[a-zA-Z]{1,6}\/){3,}[a-zA-Z]{1,3}:[a-zA-Z]{1,6})/g;
    let match;
    let lastIndex = 0;
    const result = [];

    while ((match = regex.exec(inputString)) !== null) {
        const prefix = inputString.substring(lastIndex, match.index);
        const vector = match[0];
        result.push({vector: vector, prefix: prefix});
        lastIndex = regex.lastIndex;
    }

    return result;
}

function extractPossibleNameFromFreeText(inputString, version, shortVersion) {
    const possibleCve = extractAndFormatCVE(inputString);
    if (possibleCve) {
        return shortVersion + ' ' + possibleCve.replace('CVE-', '');
    }

    const inMatcher = /in ([A-Za-z.:-]+(?: [A-Za-z.:-]+)?)/i;
    if (inMatcher.test(inputString)) {
        return shortVersion + ' ' + inMatcher.exec(inputString)[1].trim();
    }

    const scoreNameMatcher = /\d+\.\d+ +((?:CVSS ?:? ?)?\d+\.\d+)(.*)/i;
    if (scoreNameMatcher.test(inputString)) {
        const result = scoreNameMatcher.exec(inputString);
        if (result.length === 3 && result[2].length > 0  && result[2].trim().length <= 25) {
            return result[1] + ' ' + result[2].trim();
        }
        return result[1];
    }

    if (inputString.trim().length < 25) {
        return version + ' ' + inputString.trim();
    }

    return version;
}

function severityRangeColorFinder(value) {
    if (value === 0) {
        return {color: 'pastel-gray', severity: 'None'};
    } else if (value < 4) {
        return {color: 'strong-yellow', severity: 'Low'};
    } else if (value < 7) {
        return {color: 'strong-light-orange', severity: 'Medium'};
    } else if (value < 9) {
        return {color: 'strong-dark-orange', severity: 'High'};
    } else {
        return {color: 'strong-red', severity: 'Critical'};
    }
}
