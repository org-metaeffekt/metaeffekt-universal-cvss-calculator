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

const alreadyFetchedVulnerabilityData = {};
const currentlyFetchingVulnerabilityData = new Set();

const inputAddVectorByString = document.getElementById('inputAddVectorByString');
const inputLabelDefaultContent = inputAddVectorByString.innerHTML;

function httpGet(url, params, success, failure) {
    const queryString = Object.entries(params).map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`).join('&');
    const fullUrl = Object.keys(params).length > 0 ? `${url}?${queryString}` : url;

    console.log('Fetching data from:', fullUrl);

    const xhr = (() => {
        let xhr = new XMLHttpRequest();
        if ("withCredentials" in xhr) {
            xhr.open('GET', fullUrl, true);
        } else if (typeof XDomainRequest !== "undefined") {
            xhr = new XDomainRequest();
            xhr.open('GET', fullUrl);
        } else {
            return null;
        }
        return xhr;
    })();

    if (!xhr) {
        console.error('CORS not supported, cannot fetch data from:', fullUrl);
        failure('CORS not supported');
        return;
    }

    xhr.onload = () => {
        let response;
        try {
            response = JSON.parse(xhr.responseText);
        } catch (e) {
            console.error('Error parsing result:', e);
            failure(e);
            return;
        }

        try {
            console.log('Success:', response);
            success(response);
        } catch (e) {
            console.error('Error processing result:', e);
            failure(e);
        }
    };

    xhr.onerror = () => failure();

    xhr.send();
}

async function fetchVulnerabilityData(vulnerability) {
    if (!vulnerability || vulnerability === 'null' || vulnerability === 'undefined') {
        return null;
    }
    if (alreadyFetchedVulnerabilityData[vulnerability]) {
        return alreadyFetchedVulnerabilityData[vulnerability];
    }

    if (currentlyFetchingVulnerabilityData.has(vulnerability)) {
        console.log('Already fetching data for', vulnerability, '... waiting for it to finish.');
        await new Promise(resolve => {
            const check = () => {
                if (!currentlyFetchingVulnerabilityData.has(vulnerability)) resolve();
                else setTimeout(check, 100);
            };
            check();
        });
        return alreadyFetchedVulnerabilityData[vulnerability];
    }

    currentlyFetchingVulnerabilityData.add(vulnerability);
    changeInputAddVectorByStringState('loading');

    return new Promise((resolve, reject) => {
        httpGet('https://services.nvd.nist.gov/rest/json/cves/2.0', { cveId: vulnerability }, data => {
            alreadyFetchedVulnerabilityData[vulnerability] = data;
            currentlyFetchingVulnerabilityData.delete(vulnerability);
            changeInputAddVectorByStringState('success');
            resolve(data);
        }, error => {
            currentlyFetchingVulnerabilityData.delete(vulnerability);
            changeInputAddVectorByStringState('error');
            createBootstrapToast('Error fetching data', 'Error fetching data for ' + vulnerability + ': ' + error, 'danger');
            reject(error);
        });
    });
}

function changeInputAddVectorByStringState(state) {
    inputAddVectorByString.classList.remove('btn-success', 'btn-warning', 'btn-danger', 'btn-secondary');
    if (currentlyFetchingVulnerabilityData.size !== 0 && (state === 'success' || state === 'error' || state === 'default')) {
        state = 'loading';
    }
    switch (state) {
        case 'loading':
            inputAddVectorByString.classList.add('btn-secondary');
            inputAddVectorByString.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> &nbsp;NVD';
            break;
        case 'success':
            inputAddVectorByString.classList.add('btn-success');
            inputAddVectorByString.innerHTML = inputLabelDefaultContent;
            break;
        case 'error':
            inputAddVectorByString.classList.add('btn-danger');
            inputAddVectorByString.innerHTML = inputLabelDefaultContent;
            break;
        default:
            inputAddVectorByString.innerHTML = inputLabelDefaultContent;
    }
}

function removeCurrentlyFetchingVulnerabilityData(vulnerability) {
    currentlyFetchingVulnerabilityData.delete(vulnerability);
    if (currentlyFetchingVulnerabilityData.size === 0) {
        changeInputAddVectorByStringState('default');
    }
}

const extractCvssVectors = (json) => {
    const vectors = [];
    if (json && json.vulnerabilities) {
        json.vulnerabilities.forEach(vuln => {
            if (vuln.cve && vuln.cve.metrics) {
                ['cvssMetricV40', 'cvssMetricV4', 'cvssMetricV4.0', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'].forEach(metricKey => {
                    if (vuln.cve.metrics[metricKey]) {
                        vuln.cve.metrics[metricKey].forEach(metric => {
                            if (metric.cvssData) {
                                vectors.push({
                                    vector: metric.cvssData.vectorString,
                                    version: metric.cvssData.version,
                                    source: metric.source
                                });
                            }
                        });
                    }
                });
            }
        });
    }
    return vectors;
};

const extractEnglishDescription = (vulnerability, json) => {
    if (json && json.vulnerabilities) {
        const vuln = json.vulnerabilities[0];
        if (vuln.cve && vuln.cve.descriptions) {
            const desc = vuln.cve.descriptions.find(d => d.lang === 'en');
            if (desc) {
                return desc.value;
            }
        }
    }
    return null;
}

const getCvssVectors = async (vulnerability) => {
    const json = await fetchVulnerabilityData(vulnerability);
    return extractCvssVectors(json);
}

const getCvssVectorsAssumeFetched = (vulnerability) => {
    return extractCvssVectors(alreadyFetchedVulnerabilityData[vulnerability]);
}

const getEnglishDescription = async (vulnerability) => {
    const json = await fetchVulnerabilityData(vulnerability);
    return extractEnglishDescription(vulnerability, json);
}

const getEnglishDescriptionAssumeFetched = (vulnerability) => {
    return extractEnglishDescription(vulnerability, alreadyFetchedVulnerabilityData[vulnerability]);
}

function extractAndFormatCVE(text) {
    const cveRegex = /CVE-\d{4}-\d+|\d{3,6}-\d+/gi;
    const matches = text.match(cveRegex);

    if (matches && matches.length > 0) {
        let cve = matches[0];
        if (!cve.startsWith('CVE-')) {
            cve = 'CVE-' + cve;
        }
        return cve;
    }

    return null;
}
