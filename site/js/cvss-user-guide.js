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

const cvssUserGuideData = {
    'CVSS:2.0': {},

    'CVSS:3.1': {
        'AV': {
            'type': 'question',
            'question': 'Does the attacker exploit the vulnerable component via the network stack?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Must the vulnerability be exploited from a network adjacent to the target?',
                    'options': {
                        'No': {
                            'type': 'metric',
                            'metric': 'N',
                            'description': 'Vulnerability is exploitable from across the Internet, or absent more information, assume worst case.'
                        },
                        'Yes': {
                            'type': 'metric',
                            'metric': 'A',
                            'description': 'Vulnerability is exploitable across a limited physical or logical network, i.e., Bluetooth, Wi-Fi, etc.'
                        },
                    }
                },
                'No': {
                    'type': 'question',
                    'question': 'Does the attacker require physical access to the target?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'P',
                            'description': 'Attacker requires physical access to the vulnerable component.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Attack is committed through a local application vulnerability, or the attacker is able to log in locally.'
                        },
                    }
                }
            }
        },
        'AC': {
            'type': 'question',
            'question': 'Can the attacker exploit the vulnerability at will?',
            'options': {
                'Yes': {
                    'type': 'metric',
                    'metric': 'L',
                    'description': 'Attacker can exploit the vulnerability at anytime, always.'
                },
                'No': {
                    'type': 'metric',
                    'metric': 'H',
                    'description': 'Successful attack depends on conditions beyond the attacker\'s control'
                },
            }
        },
        'UI': {
            'type': 'question',
            'question': 'Does the attacker require some other person to perform an action or provide information?',
            'options': {
                'Yes': {
                    'type': 'metric',
                    'metric': 'R',
                    'description': 'Successful attack requires user interaction and depends on victims participation.'
                },
                'No': {
                    'type': 'metric',
                    'metric': 'N',
                    'description': 'Attack can be accomplished without any user interaction.'
                },
            }
        },
        'PR': {
            'type': 'question',
            'question': 'Must the attacker be authorized to the vulnerable component prior to the attack?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Are administrator privileges required to exploit the vulnerability?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'Attacker requires privileges that provide significant control over the vulnerable component, like administrator or system level access.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Attacker requires privileges that provide basic user capabilities.'
                        },
                    }
                },
                'No': {
                    'type': 'metric',
                    'metric': 'N',
                    'description': 'Attacker requires no privileges to exploit the vulnerability, i.e., an unauthorized attacker.'
                },
            }
        },
        'S': {
            'type': 'question',
            'question': 'Can the attacker affect a component whose authority is different than the vulnerable component?',
            'options': {
                'Yes': {
                    'type': 'metric',
                    'metric': 'C',
                    'description': 'Impact can be caused to systems beyond the vulnerable component.'
                },
                'No': {
                    'type': 'metric',
                    'metric': 'U',
                    'description': 'Impact is limited to the vulnerable component.'
                },
            }
        },
        'C': {
            'type': 'question',
            'question': 'Is there any impact to the confidentiality of the system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker obtain all information from the impacted component; or is the disclosed information critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'All information is disclosed to attacker; or some critical information is disclosed.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Some information can be obtained and/or the attacker does not have control over the kind or degree.'
                        },
                    }
                },
                'No': {
                    'type': 'metric',
                    'metric': 'N',
                    'description': 'No information is disclosed to the attacker.'
                },
            }
        },
        'I': {
            'type': 'question',
            'question': 'Is there any impact to the integrity of the system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker modify all the information of the impacted component; or is the modified information critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'The attacker can modify any non-critical information; or some critical information is modified.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Some information can be modified and/or the attacker does not have control over the kind or degree.'
                        },
                    }
                },
                'No': {
                    'type': 'metric',
                    'metric': 'N',
                    'description': 'No integrity loss.'
                },
            }
        },
        'A': {
            'type': 'question',
            'question': 'Is there any impact to the availability of the resource?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker completely deny access to the affected component; or is the resource critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'The affected resource is completely unavailable; or is critical and suffers reduced performance or interruption.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'The affected resource is non-critical but suffers reduced performance or interrupted operation.'
                        },
                    }
                },
                'No': {
                    'type': 'metric',
                    'metric': 'N',
                    'description': 'No availability impact.'
                },
            }
        },
        'E': {
            'type': 'question',
            'question': 'Is there any exploit code available at all (working or not)?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Is the exploit code only a proof-of-concept or more advanced?',
                    'options': {
                        'Proof of Concept': {
                            'type': 'metric',
                            'metric': 'P',
                            'description': 'The exploit code is at the proof of concept stage, indicating that it demonstrates the vulnerability’s feasibility but is not refined.'
                        },
                        'Advanced Stage': {
                            'type': 'question',
                            'question': 'Is the exploit code functional or of high maturity?',
                            'options': {
                                'Functional': {
                                    'type': 'metric',
                                    'metric': 'F',
                                    'description': 'The exploit code is functional and can be used to exploit the vulnerability under certain conditions.'
                                },
                                'High Maturity': {
                                    'type': 'metric',
                                    'metric': 'H',
                                    'description': 'The exploit code is highly mature, reliable, and either widely available or usable in most situations.'
                                }
                            }
                        }
                    }
                },
                'No': {
                    'type': 'metric',
                    'metric': 'U',
                    'description': 'No exploit code is available, or an exploit is theoretical.'
                },
            }
        },
        'RL': {
            'type': 'question',
            'question': 'Is there a remediation available for the vulnerability?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Is the official remediation a complete fix?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'O',
                            'description': 'An official patch or fix is available and it completely resolves the vulnerability.'
                        },
                        'No': {
                            'type': 'question',
                            'question': 'Is the official remediation a temporary fix or a workaround?',
                            'options': {
                                'Temporary Remediation': {
                                    'type': 'metric',
                                    'metric': 'T',
                                    'description': 'There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.'
                                },
                                'Workaround': {
                                    'type': 'metric',
                                    'metric': 'W',
                                    'description': 'There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.'
                                }
                            }
                        }
                    }
                },
                'No': {
                    'type': 'metric',
                    'metric': 'U',
                    'description': 'There is either no solution available or it is impossible to apply.'
                }
            }
        },
        'CR': {
            'type': 'question',
            'question': 'How important is it to protect the confidentiality of information in the affected component?',
            'options': {
                'Not Defined': {
                    'type': 'metric',
                    'metric': 'X',
                    'description': 'There is not enough information to determine the importance of confidentiality protection, so this option is neutral and does not impact the overall score.'
                },
                'Low': {
                    'type': 'metric',
                    'metric': 'L',
                    'description': 'Confidentiality is of low importance, and loss of confidentiality would likely have a limited adverse effect on the organization or individuals.'
                },
                'Medium': {
                    'type': 'metric',
                    'metric': 'M',
                    'description': 'Confidentiality is of medium importance, and loss of confidentiality could have a serious adverse effect on the organization or individuals.'
                },
                'High': {
                    'type': 'metric',
                    'metric': 'H',
                    'description': 'Confidentiality is of high importance, and loss of confidentiality would likely have a catastrophic adverse effect on the organization or individuals.'
                }
            }
        },
        'IR': {
            'type': 'question',
            'question': 'How important is it to maintain the integrity of information in the affected component?',
            'options': {
                'Not Defined': {
                    'type': 'metric',
                    'metric': 'X',
                    'description': 'There is not enough information to determine the importance of integrity protection, so this option is neutral and does not impact the overall score.'
                },
                'Low': {
                    'type': 'metric',
                    'metric': 'L',
                    'description': 'Integrity is of low importance, and loss of integrity would likely have a limited adverse effect on the organization or individuals.'
                },
                'Medium': {
                    'type': 'metric',
                    'metric': 'M',
                    'description': 'Integrity is of medium importance, and loss of integrity could have a serious adverse effect on the organization or individuals.'
                },
                'High': {
                    'type': 'metric',
                    'metric': 'H',
                    'description': 'Integrity is of high importance, and loss of integrity would likely have a catastrophic adverse effect on the organization or individuals.'
                }
            }
        },
        'AR': {
            'type': 'question',
            'question': 'How important is it to maintain the availability of the affected component?',
            'options': {
                'Not Defined': {
                    'type': 'metric',
                    'metric': 'X',
                    'description': 'There is not enough information to determine the importance of availability, so this option is neutral and does not impact the overall score.'
                },
                'Low': {
                    'type': 'metric',
                    'metric': 'L',
                    'description': 'Availability is of low importance, and loss of availability would likely have a limited adverse effect on the organization or individuals.'
                },
                'Medium': {
                    'type': 'metric',
                    'metric': 'M',
                    'description': 'Availability is of medium importance, and loss of availability could have a serious adverse effect on the organization or individuals.'
                },
                'High': {
                    'type': 'metric',
                    'metric': 'H',
                    'description': 'Availability is of high importance, and loss of availability would likely have a catastrophic adverse effect on the organization or individuals.'
                }
            }
        }

    },

    "CVSS:4.0": {
        'AV': {
            'type': 'question',
            'question': 'Does the attacker exploit the vulnerable component via the network stack?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Must the vulnerability be exploited from a network logically adjacent to the target?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'A',
                            'description': 'Attack is limited at the protocol level to a logically adjacent topology, e.g., Bluetooth or Wi-Fi.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'N',
                            'description': 'Vulnerability is exploitable from a remote network, e.g. across the Internet.'
                        },
                    }
                },
                'No': {
                    'type': 'question',
                    'question': 'Does the attacker require physical access to the target?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'P',
                            'description': 'Attacker requires physical access to the vulnerable component.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Attack is committed through a local application vulnerability, or the attacker is able to log in locally.'
                        },
                    }
                }
            }
        },
        'AC': {
            'type': 'question',
            'question': 'Can the attacker exploit the vulnerability at will?',
            'options': {
                'Yes': {
                    'type': 'metric',
                    'metric': 'L',
                    'description': 'Attacker can reliably exploit the vulnerability at anytime, always.'
                },
                'No': {
                    'type': 'metric',
                    'metric': 'H',
                    'description': 'An attack will always fail unless built-in security-enhancing controls are overcome.'
                },
            }
        },
        'AT': {
            'type': 'question',
            'question': 'Does a successful attack depend on specific execution conditions?',
            'options': {
                'Yes': {
                    'type': 'metric',
                    'metric': 'P',
                    'description': 'A successful attack will become more difficult unless specific, external conditions are met.'
                },
                'No': {
                    'type': 'metric',
                    'metric': 'N',
                    'description': 'The attacker can exploit the vulnerability under all or most instances of the vulnerability.'
                },
            }
        },
        'PR': {
            'type': 'question',
            'question': 'Must the attacker be authorized to the vulnerable component prior to the attack?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Are administrator privileges required to exploit the vulnerability?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'Administrator or system level privileges are required to exploit the vulnerability.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'User access privileges are required to exploit the vulnerability.'
                        },
                    }
                },
                "No": {
                    "type": "metric",
                    "metric": "N",
                    "description": "Attacker requires no privileges to exploit the vulnerability, i.e., an unauthorized attacker."
                }
            }
        },
        'UI': {
            'type': 'question',
            'question': 'Does the attacker require some other user to perform an attack?',
            'options': {
                'Yes': {
                    "type": "metric",
                    "metric": "N",
                    "description": 'Attack can be accomplished with no user interaction.'
                },
                "No": {
                    'type': 'question',
                    'question': 'Does the other user need to be an active participant?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'A',
                            'description': 'Successful exploitation of this vulnerability requires a targeted user to perform specific interactions.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'P',
                            'description': 'Successful exploitation of this vulnerability requires limited interaction by the targeted user.'
                        },
                    }
                }
            }
        },
        'VC': {
            'type': 'question',
            'question': 'Is there any impact on the confidentiality of the vulnerable system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker obtain all information from the impacted component or is the disclosed information critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'All information is disclosed to the attacker, or some critical information is disclosed.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Some information can be obtained, and/or the attacker does not have control over the kind or degree.'
                        },
                    }
                },
                "No": {
                    "type": "metric",
                    "metric": "N",
                    "description": 'No information is disclosed to the attacker.'
                }
            }
        },
        'VI': {
            'type': 'question',
            'question': 'Is there any impact on the integrity of the vulnerable system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker modify all information from the impacted component or is the modified information critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'The attacker can modify any non-critical information, or some critical information.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Some information can be modified, and/or the attacker does not have control over the kind or degree.'
                        },
                    }
                },
                "No": {
                    "type": "metric",
                    "metric": "N",
                    "description": 'No information is modified by the attacker.'
                }
            }
        },
        'VA': {
            'type': 'question',
            'question': 'Is there any impact on the availability of a resource on the vulnerable system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker completely deny access to the affected component, or is the resource critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'The affected resource is completely unavailable Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Vulnerable System.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'The affected resource is non-critical, but suffers reduced performance or intermittent operation.'
                        },
                    }
                },
                "No": {
                    "type": "metric",
                    "metric": "N",
                    "description": 'No availability impact.'
                }
            }
        },
        'SC': {
            'type': 'question',
            'question': 'Is there any impact on the confidentiality of the subsequent system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker obtain all information from the impacted component or is the disclosed information critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'All information is disclosed to the attacker, or some critical information is disclosed.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Some information can be obtained, and/or the attacker does not have control over the kind or degree.'
                        },
                    }
                },
                "No": {
                    "type": "metric",
                    "metric": "N",
                    "description": 'No information is disclosed to the attacker.'
                }
            }
        },
        'SI': {
            'type': 'question',
            'question': 'Is there any impact on the integrity of the subsequent system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker modify all information from the impacted component or is the modified information critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'The attacker can modify any non-critical information, or some critical information.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'Some information can be modified, and/or the attacker does not have control over the kind or degree.'
                        },
                    }
                },
                "No": {
                    "type": "metric",
                    "metric": "N",
                    "description": 'No information is modified by the attacker.'
                }
            }
        },
        'SA': {
            'type': 'question',
            'question': 'Is there any impact on the availability of a resource on the subsequent system?',
            'options': {
                'Yes': {
                    'type': 'question',
                    'question': 'Can the attacker completely deny access to the affected component, or is the resource critical?',
                    'options': {
                        'Yes': {
                            'type': 'metric',
                            'metric': 'H',
                            'description': 'The affected resource is completely unavailable Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Subsequent System.'
                        },
                        'No': {
                            'type': 'metric',
                            'metric': 'L',
                            'description': 'The affected resource is non-critical, but suffers reduced performance or intermittent operation.'
                        },
                    }
                },
                "No": {
                    "type": "metric",
                    "metric": "N",
                    "description": 'No availability impact.'
                }
            }
        }
    }
}

copyCvssUserGuide('CVSS:3.1', 'AV', 'MAV');
copyCvssUserGuide('CVSS:3.1', 'AC', 'MAC');
copyCvssUserGuide('CVSS:3.1', 'UI', 'MUI');
copyCvssUserGuide('CVSS:3.1', 'PR', 'MPR');
copyCvssUserGuide('CVSS:3.1', 'S', 'MS');
copyCvssUserGuide('CVSS:3.1', 'C', 'MC');
copyCvssUserGuide('CVSS:3.1', 'I', 'MI');
copyCvssUserGuide('CVSS:3.1', 'A', 'MA');

copyCvssUserGuide('CVSS:4.0', 'AV', 'MAV');
copyCvssUserGuide('CVSS:4.0', 'AC', 'MAC');
copyCvssUserGuide('CVSS:4.0', 'AT', 'MAT');
copyCvssUserGuide('CVSS:4.0', 'UI', 'MUI');
copyCvssUserGuide('CVSS:4.0', 'PR', 'MPR');
copyCvssUserGuide('CVSS:4.0', 'VC', 'MVC');
copyCvssUserGuide('CVSS:4.0', 'VI', 'MVI');
copyCvssUserGuide('CVSS:4.0', 'VA', 'MVA');
copyCvssUserGuide('CVSS:4.0', 'SC', 'MSC');
copyCvssUserGuide('CVSS:4.0', 'SI', 'MSI');
copyCvssUserGuide('CVSS:4.0', 'SA', 'MSA');

function copyCvssUserGuide(cvssVersion, metric, newMetric) {
    if (cvssUserGuideData[cvssVersion] && cvssUserGuideData[cvssVersion][metric]) {
        cvssUserGuideData[cvssVersion][newMetric] = cvssUserGuideData[cvssVersion][metric];
    }
}

function findCvssUserGuide(version, metric) {
    if (cvssUserGuideData[version] && cvssUserGuideData[version][metric]) {
        return cvssUserGuideData[version][metric];
    }
    return null;
}

function openUserGuideModal(vectorInstance, component, userGuide, completionCallback = undefined) {
    const modal = new bootstrap.Modal(document.getElementById('cvssUserGuideModal'));
    const modalTitle = document.getElementById('cvssUserGuideModalLabel');
    modalTitle.innerText = `${vectorInstance.getVectorName()} ${component.shortName} - User Guide`;
    const modalBody = document.getElementById('cvssUserGuideModalBody');
    modalBody.innerHTML = `
Answer the following questions to determine the value of the <b>${component.name} (${component.shortName})</b> metric.
`;

    function createQuestionContent(questionData, container) {
        try {
            if (questionData.type === 'question') {
                const questionDiv = document.createElement('h5');
                questionDiv.innerText = questionData.question;
                questionDiv.classList.add('mt-4')
                container.appendChild(questionDiv);

                Object.entries(questionData.options).forEach(([optionText, nextQuestion]) => {
                    if (nextQuestion.type === 'metric') {
                        const card = document.createElement('div');
                        card.classList.add('card', 'm-2');
                        card.style.cursor = 'pointer';

                        const cardBody = document.createElement('div');
                        cardBody.classList.add('card-body');

                        const cardTitle = document.createElement('h5');
                        cardTitle.classList.add('card-title');
                        cardTitle.innerText = optionText + ' (' + nextQuestion.metric + ')';

                        const cardText = document.createElement('p');
                        cardText.classList.add('card-text');
                        cardText.innerText = `${nextQuestion.description}`;

                        card.onclick = () => applyMetric(nextQuestion);

                        cardBody.appendChild(cardTitle);
                        cardBody.appendChild(cardText);
                        card.appendChild(cardBody);
                        container.appendChild(card);
                    } else {
                        const card = document.createElement('div');
                        card.classList.add('card', 'm-2');
                        card.style.cursor = 'pointer';

                        const cardBody = document.createElement('div');
                        cardBody.classList.add('card-body');

                        const cardTitle = document.createElement('h5');
                        cardTitle.classList.add('card-title', 'mb-0');
                        cardTitle.innerText = optionText;

                        card.onclick = () => {
                            disableAllButtons(container);
                            createQuestionContent(nextQuestion, container);
                            card.classList.add('bg-primary', 'text-white');
                        };

                        cardBody.appendChild(cardTitle);
                        card.appendChild(cardBody);
                        container.appendChild(card);
                    }
                });
            }
        } catch (e) {
            console.error(e);
            // error toast
            createBootstrapToast('Error in User Guide data', 'Failed to load the User Guide data for this attribute.', 'error');
        }
    }

    function disableAllButtons(container) {
        Array.from(container.getElementsByTagName('button')).forEach(button => {
            button.disabled = true;
        });
        Array.from(container.getElementsByTagName('div')).forEach(div => {
            div.style.cursor = 'default';
            div.onclick = undefined;
            if (div.classList.contains('card')) {
                div.style.opacity = '0.5';
            }
        });
    }

    function applyMetric(metricData) {
        setTimeout(() => {
            modal.hide();
            vectorInstance.applyComponentString(component.shortName, metricData.metric);
            if (completionCallback) completionCallback();
        }, 100);
    }

    createQuestionContent(userGuide, modalBody);
    modal.show();
}
