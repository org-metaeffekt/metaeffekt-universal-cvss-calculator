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
import {
    ComponentCategory,
    CvssVector,
    NumberVectorComponentValue,
    VectorComponent,
    VectorComponentValue
} from "../CvssVector";

export class Cvss2Components {
    public static readonly BASE_CATEGORY: ComponentCategory = {
        name: 'base',
        description: 'Represents the intrinsic and fundamental characteristics of a vulnerability that are constant over time and user environments.'
    };

    public static readonly AV_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will result in no score being calculated.'
        },
        L: {
            shortName: 'L',
            value: 0.395,
            name: 'Local',
            jsonSchemaName: 'LOCAL',
            description: 'A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. Examples of locally exploitable vulnerabilities are peripheral attacks such as Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo).'
        },
        A: {
            shortName: 'A',
            value: 0.646,
            name: 'Adjacent Network',
            abbreviatedName: 'Adj. Network',
            jsonSchemaName: 'ADJACENT_NETWORK',
            description: 'A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.  Examples of local networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.'
        },
        N: {
            shortName: 'N',
            value: 1.000,
            name: 'Network',
            jsonSchemaName: 'NETWORK',
            description: 'A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". An example of a network attack is an RPC buffer overflow.'
        }
    };

    public static readonly AV = {
        name: 'Access Vector',
        shortName: 'AV',
        subCategory: 'Exploitability Metrics',
        description: 'This metric reflects how the vulnerability is exploited. The more remote an attacker can be to attack a host, the greater the vulnerability score.',
        values: [
            Cvss2Components.AV_VALUES.ND,
            Cvss2Components.AV_VALUES.L,
            Cvss2Components.AV_VALUES.A,
            Cvss2Components.AV_VALUES.N
        ] as NumberVectorComponentValue[]
    };

    public static readonly AC_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will result in no score being calculated.'
        },
        H: {
            shortName: 'H',
            value: 0.35,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Specialized access conditions exist. For example, an attacker can only exploit the vulnerability under very specialized conditions.'
        },
        M: {
            shortName: 'M',
            value: 0.61,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'The access conditions are somewhat specialized. For example, the attacker can only exploit the vulnerability under certain conditions.'
        },
        L: {
            shortName: 'L',
            value: 0.71,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Specialized access conditions or extenuating circumstances do not exist. For example, an attacker can exploit the vulnerability under most conditions.'
        }
    };

    public static readonly AC = {
        name: 'Access Complexity',
        shortName: 'AC',
        subCategory: 'Exploitability Metrics',
        description: 'This metric measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. For example, consider a buffer overflow in an Internet service: If the vulnerability is exploitable only once a user has been authenticated by the service, the vulnerability is only "Medium" complexity. If, however, the vulnerability can be exploited anonymously, it is "Low" complexity.',
        values: [
            Cvss2Components.AC_VALUES.ND,
            Cvss2Components.AC_VALUES.H,
            Cvss2Components.AC_VALUES.M,
            Cvss2Components.AC_VALUES.L
        ] as NumberVectorComponentValue[]
    };

    public static readonly Au_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will result in no score being calculated.'
        },
        M: {
            shortName: 'M',
            value: 0.45,
            name: 'Multiple',
            jsonSchemaName: 'MULTIPLE',
            description: 'Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. An example is an attacker authenticating to an operating system in addition to providing credentials to access an application hosted on that system.'
        },
        S: {
            shortName: 'S',
            value: 0.56,
            name: 'Single',
            jsonSchemaName: 'SINGLE',
            description: 'The vulnerability requires an attacker to be logged into the system (such as at a command line or via a desktop session or web interface).'
        },
        N: {
            shortName: 'N',
            value: 0.704,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'Authentication is not required to exploit the vulnerability.'
        }
    };

    public static readonly Au = {
        name: 'Authentication',
        shortName: 'Au',
        subCategory: 'Exploitability Metrics',
        description: 'This metric measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. "Multiple" means that the attacker must authenticate two or more times, "Single" means that the attacker must authenticate once, and "None" means that the attacker need not authenticate at all to exploit the vulnerability.',
        values: [
            Cvss2Components.Au_VALUES.ND,
            Cvss2Components.Au_VALUES.M,
            Cvss2Components.Au_VALUES.S,
            Cvss2Components.Au_VALUES.N
        ] as NumberVectorComponentValue[]
    };

    public static readonly C_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will result in no score being calculated.'
        },
        N: {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no impact to the confidentiality of the system.'
        },
        P: {
            shortName: 'P',
            value: 0.275,
            name: 'Partial',
            jsonSchemaName: 'PARTIAL',
            description: 'There is considerable informational disclosure. Access to some system files is possible, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. An example is a vulnerability that divulges only certain tables in a database.'
        },
        C: {
            shortName: 'C',
            value: 0.660,
            name: 'Complete',
            jsonSchemaName: 'COMPLETE',
            description: 'There is total information disclosure, resulting in all system files being revealed. The attacker is able to read all of the system\'s data (memory, files, etc.)'
        }
    };

    public static readonly C = {
        name: 'Confidentiality Impact',
        shortName: 'C',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.',
        values: [
            Cvss2Components.C_VALUES.ND,
            Cvss2Components.C_VALUES.N,
            Cvss2Components.C_VALUES.P,
            Cvss2Components.C_VALUES.C
        ] as NumberVectorComponentValue[]
    };

    public static readonly I_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will result in no score being calculated.'
        },
        N: {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no impact to the integrity of the system.'
        },
        P: {
            shortName: 'P',
            value: 0.275,
            name: 'Partial',
            jsonSchemaName: 'PARTIAL',
            description: 'Modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited. For example, system or application files may be overwritten or modified, but either the attacker has no control over which files are affected or the attacker can modify files within only a limited context or scope.'
        },
        C: {
            shortName: 'C',
            value: 0.660,
            name: 'Complete',
            jsonSchemaName: 'COMPLETE',
            description: 'There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system.'
        }
    };

    public static readonly I = {
        name: 'Integrity Impact',
        shortName: 'I',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and guaranteed veracity of information.',
        values: [
            Cvss2Components.I_VALUES.ND,
            Cvss2Components.I_VALUES.N,
            Cvss2Components.I_VALUES.P,
            Cvss2Components.I_VALUES.C
        ] as NumberVectorComponentValue[]
    };

    public static readonly A_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will result in no score being calculated.'
        },
        N: {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no impact to availability within the impacted component.'
        },
        P: {
            shortName: 'P',
            value: 0.275,
            name: 'Partial',
            jsonSchemaName: 'PARTIAL',
            description: 'There is reduced performance or interruptions in resource availability. An example is a network-based flood attack that permits a limited number of successful connections to an Internet service.'
        },
        C: {
            shortName: 'C',
            value: 0.660,
            name: 'Complete',
            jsonSchemaName: 'COMPLETE',
            description: 'There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable.'
        }
    };

    public static readonly A = {
        name: 'Availability Impact',
        shortName: 'A',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the impacted component, this metric refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component. This metric considers only the availability of the impacted component itself.',
        values: [
            Cvss2Components.A_VALUES.ND,
            Cvss2Components.A_VALUES.N,
            Cvss2Components.A_VALUES.P,
            Cvss2Components.A_VALUES.C
        ] as NumberVectorComponentValue[]
    };

    public static readonly BASE_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.AV, this.AC, this.Au, this.C, this.I, this.A
    ];

    public static readonly TEMPORAL_CATEGORY: ComponentCategory = {
        name: 'temporal',
        description: 'The threat posed by a vulnerability may change over time. Three such factors that CVSS captures are: confirmation of the technical details of a vulnerability, the remediation status of the vulnerability, and the availability of exploit code or techniques. Since temporal metrics are optional they each include a metric value that has no effect on the score.'
    };

    public static readonly E_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        U: {
            shortName: 'U',
            value: 0.85,
            name: 'Unproven',
            jsonSchemaName: 'UNPROVEN',
            description: 'No exploit code is available, or an exploit is entirely theoretical.'
        },
        POC: {
            shortName: 'POC',
            value: 0.9,
            name: 'Proof-of-concept',
            abbreviatedName: 'Proof-of-conc.',
            jsonSchemaName: 'PROOF_OF_CONCEPT',
            description: 'Proof-of-concept exploit code or an attack demonstration that is not practical for most systems is available. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.'
        },
        F: {
            shortName: 'F',
            value: 0.95,
            name: 'Functional',
            jsonSchemaName: 'FUNCTIONAL',
            description: 'Functional exploit code is available. The code works in most situations where the vulnerability exists.'
        },
        H: {
            shortName: 'H',
            value: 1.0,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Either the vulnerability is exploitable by functional mobile autonomous code, or no exploit is required (manual trigger) and details are widely available. The code works in every situation, or is actively being delivered via a mobile autonomous agent (such as a worm or virus).'
        }
    };

    public static readonly E = {
        name: 'Exploitability',
        shortName: 'E',
        description: 'This metric measures the current state of exploit techniques or code availability. "Unproven that exploit exists" is the lowest impact and "Proof-of-concept code" is the highest impact.',
        values: [
            Cvss2Components.E_VALUES.ND,
            Cvss2Components.E_VALUES.U,
            Cvss2Components.E_VALUES.POC,
            Cvss2Components.E_VALUES.F,
            Cvss2Components.E_VALUES.H
        ] as NumberVectorComponentValue[]
    };

    public static readonly RL_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        OF: {
            shortName: 'OF',
            value: 0.87,
            name: 'Official Fix',
            abbreviatedName: 'Off. Fix',
            jsonSchemaName: 'OFFICIAL_FIX',
            description: 'A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.'
        },
        TF: {
            shortName: 'TF',
            value: 0.9,
            name: 'Temporary Fix',
            abbreviatedName: 'Temp. Fix',
            jsonSchemaName: 'TEMPORARY_FIX',
            description: 'There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.'
        },
        W: {
            shortName: 'W',
            value: 0.95,
            name: 'Workaround',
            jsonSchemaName: 'WORKAROUND',
            description: 'There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.'
        },
        U: {
            shortName: 'U',
            value: 1.0,
            name: 'Unavailable',
            jsonSchemaName: 'UNAVAILABLE',
            description: 'There is either no solution available or it is impossible to apply.'
        }
    };

    public static readonly RL = {
        name: 'Remediation Level',
        shortName: 'RL',
        description: 'This metric measures the remediation level of a vulnerability. "Official fix" is the lowest impact and "Unavailable" is the highest impact.',
        values: [
            Cvss2Components.RL_VALUES.ND,
            Cvss2Components.RL_VALUES.OF,
            Cvss2Components.RL_VALUES.TF,
            Cvss2Components.RL_VALUES.W,
            Cvss2Components.RL_VALUES.U
        ] as NumberVectorComponentValue[]
    };

    public static readonly RC_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        UC: {
            shortName: 'UC',
            value: 0.9,
            name: 'Unconfirmed',
            jsonSchemaName: 'UNCONFIRMED',
            description: 'There is little confidence in the existence of this vulnerability. The report is unconfirmed, or the source is not known.'
        },
        UR: {
            shortName: 'UR',
            value: 0.95,
            name: 'Uncorroborated',
            jsonSchemaName: 'UNCORROBORATED',
            description: 'There is reasonable confidence in the existence of this vulnerability, but the technical details are not known publicly. The report is unconfirmed.'
        },
        C: {
            shortName: 'C',
            value: 1.0,
            name: 'Confirmed',
            jsonSchemaName: 'CONFIRMED',
            description: 'The existence of this vulnerability is confirmed, but the details are not known publicly. An exploit has been observed, or proof-of-concept exploit code is available. The bugtraq ID or CVE ID has been made public.'
        },
    };

    public static readonly RC = {
        name: 'Report Confidence',
        shortName: 'RC',
        description: 'This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details. "Unconfirmed" is the lowest confidence and "Confirmed" is the highest.',
        values: [
            Cvss2Components.RC_VALUES.ND,
            Cvss2Components.RC_VALUES.UC,
            Cvss2Components.RC_VALUES.UR,
            Cvss2Components.RC_VALUES.C
        ] as NumberVectorComponentValue[]
    };

    public static readonly TEMPORAL_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.E, this.RL, this.RC
    ];

    public static readonly ENVIRONMENTAL_CATEGORY: ComponentCategory = {
        name: 'environmental',
        description: 'Different environments can have an immense bearing on the risk that a vulnerability poses to an organization and its stakeholders. The CVSS environmental metric group captures the characteristics of a vulnerability that are associated with a user\'s IT environment. Since environmental metrics are optional they each include a metric value that has no effect on the score.'
    };

    public static readonly CDP_VALUES = {
        ND: {
            shortName: 'ND',
            value: 0.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        N: {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no potential for loss of life, physical assets, productivity or revenue.'
        },
        L: {
            shortName: 'L',
            value: 0.1,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'A successful exploit of this vulnerability may result in slight physical or property damage. Or, there may be a slight loss of revenue or productivity to the organization.'
        },
        LM: {
            shortName: 'LM',
            value: 0.3,
            name: 'Low-Medium',
            abbreviatedName: 'Low-Med.',
            jsonSchemaName: 'LOW_MEDIUM',
            description: 'A successful exploit of this vulnerability may result in moderate physical or property damage. Or, there may be a moderate loss of revenue or productivity to the organization.'
        },
        MH: {
            shortName: 'MH',
            value: 0.4,
            name: 'Medium-High',
            abbreviatedName: 'Med.-High',
            jsonSchemaName: 'MEDIUM_HIGH',
            description: 'A successful exploit of this vulnerability may result in significant physical or property damage or loss. Or, there may be a significant loss of revenue or productivity.'
        },
        H: {
            shortName: 'H',
            value: 0.5,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'A successful exploit of this vulnerability may result in catastrophic physical or property damage and loss. Or, there may be a catastrophic loss of revenue or productivity.'
        },
    };

    public static readonly CDP = {
        name: 'Collateral Damage Potential',
        shortName: 'CDP',
        subCategory: 'General Modifiers',
        description: 'This metric measures the potential for loss of life or physical assets resulting from a vulnerability. "None" is the lowest impact and "High" is the highest impact.',
        values: [
            Cvss2Components.CDP_VALUES.ND,
            Cvss2Components.CDP_VALUES.N,
            Cvss2Components.CDP_VALUES.L,
            Cvss2Components.CDP_VALUES.LM,
            Cvss2Components.CDP_VALUES.MH,
            Cvss2Components.CDP_VALUES.H
        ] as NumberVectorComponentValue[]
    };

    public static readonly TD_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        N: {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no (0%) target distribution.'
        },
        L: {
            shortName: 'L',
            value: 0.25,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'There is a small (< 25%) target distribution.'
        },
        M: {
            shortName: 'M',
            value: 0.75,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'There is a medium (26-75%) target distribution.'
        },
        H: {
            shortName: 'H',
            value: 1.0,
            name: 'High',
            description: 'There is a high (> 75%) target distribution.'
        }
    };

    public static readonly TD = {
        name: 'Target Distribution',
        shortName: 'TD',
        subCategory: 'General Modifiers',
        description: 'This metric measures the proportion of vulnerable systems that could be affected by an attack. It is meant to represent the proportion of vulnerable systems that an attacker can expect to target. "None" is the lowest impact and "High" is the highest impact.',
        values: [
            Cvss2Components.TD_VALUES.ND,
            Cvss2Components.TD_VALUES.N,
            Cvss2Components.TD_VALUES.L,
            Cvss2Components.TD_VALUES.M,
            Cvss2Components.TD_VALUES.H
        ] as NumberVectorComponentValue[]
    };

    public static readonly CR_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        L: {
            shortName: 'L',
            value: 0.5,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        M: {
            shortName: 'M',
            value: 1.0,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of confidentiality is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        H: {
            shortName: 'H',
            value: 1.51,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    };

    public static readonly CR = {
        name: 'Confidentiality Requirement',
        shortName: 'CR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric measures the need for confidentiality of the vulnerable component to the user. For example, an attacker that exploits a vulnerability that exists on a network boundary and requires no privileges has a low need for the confidentiality of the vulnerable component. Conversely, an attacker that exploits a vulnerability that exists on the same system as the vulnerable component and requires Privileged access to the system in order to exploit it has a high need for confidentiality. "Not Defined" is the lowest impact and "High" is the highest impact.',
        values: [
            Cvss2Components.CR_VALUES.ND,
            Cvss2Components.CR_VALUES.L,
            Cvss2Components.CR_VALUES.M,
            Cvss2Components.CR_VALUES.H
        ] as NumberVectorComponentValue[]
    };

    public static readonly IR_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        L: {
            shortName: 'L',
            value: 0.5,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        M: {
            shortName: 'M',
            value: 1.0,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of integrity is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        H: {
            shortName: 'H',
            value: 1.51,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    };

    public static readonly IR = {
        name: 'Integrity Requirement',
        shortName: 'IR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric measures the need for integrity of the vulnerable component to a user. For example, an attacker that exploits a vulnerability that exists on a network boundary and requires no privileges has a low need for the integrity of the vulnerable component. Conversely, an attacker that exploits a vulnerability that exists on the same system as the vulnerable component and requires Privileged access to the system in order to exploit it has a high need for integrity. "Not Defined" is the lowest impact and "High" is the highest impact.',
        values: [
            Cvss2Components.IR_VALUES.ND,
            Cvss2Components.IR_VALUES.L,
            Cvss2Components.IR_VALUES.M,
            Cvss2Components.IR_VALUES.H
        ] as NumberVectorComponentValue[]
    };

    public static readonly AR_VALUES = {
        ND: {
            shortName: 'ND',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
        },
        L: {
            shortName: 'L',
            value: 0.5,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        M: {
            shortName: 'M',
            value: 1.0,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of availability is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        H: {
            shortName: 'H',
            value: 1.51,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    };

    public static readonly AR = {
        name: 'Availability Requirement',
        shortName: 'AR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric measures the need for availability of the vulnerable component to a user. For example, an attacker that exploits a vulnerability that exists on a network boundary and requires no privileges has a low need for the availability of the vulnerable component. Conversely, an attacker that exploits a vulnerability that exists on the same system as the vulnerable component and requires Privileged access to the system in order to exploit it has a high need for availability. "Not Defined" is the lowest impact and "High" is the highest impact.',
        values: [
            Cvss2Components.AR_VALUES.ND,
            Cvss2Components.AR_VALUES.L,
            Cvss2Components.AR_VALUES.M,
            Cvss2Components.AR_VALUES.H
        ] as NumberVectorComponentValue[]
    };

    public static readonly ENVIRONMENTAL_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.CDP, this.TD, this.CR, this.IR, this.AR
    ];

    static readonly REGISTERED_COMPONENTS = new Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>();

    static {
        Cvss2Components.REGISTERED_COMPONENTS.set(Cvss2Components.BASE_CATEGORY, Cvss2Components.BASE_CATEGORY_VALUES);
        Cvss2Components.REGISTERED_COMPONENTS.set(Cvss2Components.TEMPORAL_CATEGORY, Cvss2Components.TEMPORAL_CATEGORY_VALUES);
        Cvss2Components.REGISTERED_COMPONENTS.set(Cvss2Components.ENVIRONMENTAL_CATEGORY, Cvss2Components.ENVIRONMENTAL_CATEGORY_VALUES);
    }

    public static readonly ATTRIBUTE_SEVERITY_ORDER: VectorComponentValue[][] = CvssVector._reorderAttributeSeverityOrder([
        Cvss2Components.AC_VALUES.ND,
        Cvss2Components.AV_VALUES.ND,
        Cvss2Components.Au_VALUES.ND,
        Cvss2Components.C_VALUES.ND,
        Cvss2Components.I_VALUES.ND,
        Cvss2Components.A_VALUES.ND,
        Cvss2Components.C_VALUES.N,
        Cvss2Components.I_VALUES.N,
        Cvss2Components.A_VALUES.N,
        Cvss2Components.CDP_VALUES.N,
        Cvss2Components.CDP_VALUES.ND,
        Cvss2Components.TD_VALUES.N,
        Cvss2Components.CDP_VALUES.L,
        Cvss2Components.TD_VALUES.L,
        Cvss2Components.C_VALUES.P,
        Cvss2Components.I_VALUES.P,
        Cvss2Components.A_VALUES.P,
        Cvss2Components.CDP_VALUES.LM,
        Cvss2Components.AC_VALUES.H,
        Cvss2Components.AV_VALUES.L,
        Cvss2Components.CDP_VALUES.MH,
        Cvss2Components.Au_VALUES.M,
        Cvss2Components.CDP_VALUES.H,
        Cvss2Components.Au_VALUES.S,
        Cvss2Components.AC_VALUES.M,
        Cvss2Components.AV_VALUES.A,
        Cvss2Components.C_VALUES.C,
        Cvss2Components.I_VALUES.C,
        Cvss2Components.A_VALUES.C,
        Cvss2Components.Au_VALUES.N,
        Cvss2Components.AC_VALUES.L,
        Cvss2Components.TD_VALUES.M,
        Cvss2Components.E_VALUES.U,
        Cvss2Components.RL_VALUES.OF,
        Cvss2Components.E_VALUES.POC,
        Cvss2Components.RL_VALUES.TF,
        Cvss2Components.RL_VALUES.W,
        Cvss2Components.RC_VALUES.UC,
        Cvss2Components.AV_VALUES.N,
        Cvss2Components.E_VALUES.F,
        Cvss2Components.E_VALUES.H,
        Cvss2Components.E_VALUES.ND,
        Cvss2Components.RL_VALUES.U,
        Cvss2Components.RL_VALUES.ND,
        Cvss2Components.RC_VALUES.UR,
        Cvss2Components.RC_VALUES.C,
        Cvss2Components.RC_VALUES.ND,
        Cvss2Components.TD_VALUES.H,
        Cvss2Components.TD_VALUES.ND,
        Cvss2Components.CR_VALUES.L,
        Cvss2Components.CR_VALUES.M,
        Cvss2Components.IR_VALUES.L,
        Cvss2Components.IR_VALUES.M,
        Cvss2Components.AR_VALUES.L,
        Cvss2Components.AR_VALUES.M,
        Cvss2Components.CR_VALUES.ND,
        Cvss2Components.IR_VALUES.ND,
        Cvss2Components.AR_VALUES.ND,
        Cvss2Components.CR_VALUES.H,
        Cvss2Components.IR_VALUES.H,
        Cvss2Components.AR_VALUES.H
    ]);
}
