/*
{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2024-01-09T13:42:06.403",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2016-6318",
        "sourceIdentifier": "secalert@redhat.com",
        "published": "2016-09-07T19:28:12.457",
        "lastModified": "2023-02-12T23:24:53.917",
        "vulnStatus": "Modified",
        "descriptions": [
          {
            "lang": "en",
            "value": "Stack-based buffer overflow in the FascistGecosUser function in lib/fascist.c in cracklib allows local users to cause a denial of service (application crash) or gain privileges via a long GECOS field, involving longbuffer."
          },
          {
            "lang": "es",
            "value": "Desbordamiento de búfer basado en pila en la función FascistGecosUser en lib/fascist.c en cracklib permite a usuarios locales provocar una denegación de servicio (caída de aplicacion) u obtener privilegios a través de campos GECOS largos, implicando un búfer largo."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "attackVector": "LOCAL",
                "attackComplexity": "LOW",
                "privilegesRequired": "LOW",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH",
                "baseScore": 7.8,
                "baseSeverity": "HIGH"
              },
              "exploitabilityScore": 1.8,
              "impactScore": 5.9
            }
          ],
          "cvssMetricV2": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "2.0",
                "vectorString": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
                "accessVector": "LOCAL",
                "accessComplexity": "LOW",
                "authentication": "NONE",
                "confidentialityImpact": "COMPLETE",
                "integrityImpact": "COMPLETE",
                "availabilityImpact": "COMPLETE",
                "baseScore": 7.2
              },
              "baseSeverity": "HIGH",
              "exploitabilityScore": 3.9,
              "impactScore": 10,
              "acInsufInfo": false,
              "obtainAllPrivilege": false,
              "obtainUserPrivilege": false,
              "obtainOtherPrivilege": false,
              "userInteractionRequired": false
            }
          ]
        },
        "weaknesses": [
          {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [
              {
                "lang": "en",
                "value": "CWE-787"
              }
            ]
          }
        ],
        "configurations": [
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:cracklib_project:cracklib:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.9.0",
                    "versionEndExcluding": "2.9.6",
                    "matchCriteriaId": "3D5FE270-3F00-44E0-975F-D14EADAEFE3B"
                  }
                ]
              }
            ]
          },
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:o:opensuse:leap:42.1:*:*:*:*:*:*:*",
                    "matchCriteriaId": "4863BE36-D16A-4D75-90D9-FD76DB5B48B7"
                  }
                ]
              }
            ]
          },
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*",
                    "matchCriteriaId": "C11E6FB0-C8C0-4527-9AA0-CB9B316F8F43"
                  }
                ]
              }
            ]
          }
        ],
        "references": [
          {
            "url": "http://lists.opensuse.org/opensuse-updates/2016-08/msg00122.html",
            "source": "secalert@redhat.com",
            "tags": [
              "Mailing List",
              "Third Party Advisory"
            ]
          },
          {
            "url": "http://www.openwall.com/lists/oss-security/2016/08/16/2",
            "source": "secalert@redhat.com",
            "tags": [
              "Mailing List",
              "Third Party Advisory"
            ]
          },
          {
            "url": "http://www.securityfocus.com/bid/92478",
            "source": "secalert@redhat.com",
            "tags": [
              "Third Party Advisory",
              "VDB Entry"
            ]
          },
          {
            "url": "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E",
            "source": "secalert@redhat.com"
          },
          {
            "url": "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E",
            "source": "secalert@redhat.com"
          },
          {
            "url": "https://lists.debian.org/debian-lts-announce/2020/05/msg00023.html",
            "source": "secalert@redhat.com",
            "tags": [
              "Mailing List",
              "Third Party Advisory"
            ]
          },
          {
            "url": "https://security.gentoo.org/glsa/201612-25",
            "source": "secalert@redhat.com",
            "tags": [
              "Third Party Advisory"
            ]
          }
        ]
      }
    }
  ]
}
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