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
const fetchVulnerabilityData = async (vulnerability) => {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${vulnerability}`;
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching data: ', error);
    }
};

const extractCvssVectors = (json) => {
    const vectors = [];
    if (json && json.vulnerabilities) {
        json.vulnerabilities.forEach(vuln => {
            if (vuln.cve && vuln.cve.metrics) {
                ['cvssMetricV40', 'cvssMetricV4', 'cvssMetricV4.0', 'cvssMetricV31', 'cvssMetricV2'].forEach(metricKey => {
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

const extractEnglishDescription = (json) => {
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