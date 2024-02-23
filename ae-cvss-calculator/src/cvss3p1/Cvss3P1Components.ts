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
    BooleanVectorComponentValue,
    ChangedNumberVectorComponentValue,
    ComponentCategory,
    NumberVectorComponentValue,
    VectorComponent,
    VectorComponentValue
} from "../CvssVector";

export class Cvss3P1Components {
    private static readonly CONFIDENTIALITY_IMPACT = [
        {
            shortName: 'X',
            value: 0.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no loss of confidentiality within the impacted component.'
        },
        {
            shortName: 'L',
            value: 0.22,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.'
        },
        {
            shortName: 'H',
            value: 0.56,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator\'s password, or private encryption keys of a web server.'
        }
    ] as NumberVectorComponentValue[];

    private static readonly INTEGRITY_IMPACT = [
        {
            shortName: 'X',
            value: 0.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no loss of integrity within the impacted component.'
        },
        {
            shortName: 'L',
            value: 0.22,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.'
        },
        {
            shortName: 'H',
            value: 0.56,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.'
        }
    ] as NumberVectorComponentValue[];

    private static readonly AVAILABILITY_IMPACT = [
        {
            shortName: 'X',
            value: 0.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        {
            shortName: 'N',
            value: 0.0,
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no impact to availability within the impacted component.'
        },
        {
            shortName: 'L',
            value: 0.22,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.'
        },
        {
            shortName: 'H',
            value: 0.56,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).'
        }
    ] as NumberVectorComponentValue[];

    private static readonly CONFIDENTIALITY_REQUIREMENT = [
        {
            shortName: 'X',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.'
        },
        {
            shortName: 'L',
            value: 0.5,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        {
            shortName: 'M',
            value: 1.0,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of Confidentiality is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        {
            shortName: 'H',
            value: 1.5,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    ] as NumberVectorComponentValue[];

    private static readonly INTEGRITY_REQUIREMENT = [
        {
            shortName: 'X',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.'
        },
        {
            shortName: 'L',
            value: 0.5,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        {
            shortName: 'M',
            value: 1.0,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of Integrity is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        {
            shortName: 'H',
            value: 1.5,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    ] as NumberVectorComponentValue[];

    private static readonly AVAILABILITY_REQUIREMENT = [
        {
            shortName: 'X',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.'
        },
        {
            shortName: 'L',
            value: 0.5,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of Availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        {
            shortName: 'M',
            value: 1.0,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of Availability is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        {
            shortName: 'H',
            value: 1.5,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of Availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    ] as NumberVectorComponentValue[];

    private static readonly TEMPLATE_CIA_REQUIREMENT_MODIFIED = [
        {
            shortName: 'X',
            value: 1.0,
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        {
            shortName: 'L',
            value: 0.5,
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'There is no impact to the integrity of the system.'
        },
        {
            shortName: 'M',
            value: 1.0,
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'There is a partial compromise of system integrity.'
        },
        {
            shortName: 'H',
            value: 1.5,
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total compromise of system integrity.'
        }
    ] as NumberVectorComponentValue[];

    public static readonly BASE_CATEGORY: ComponentCategory = {
        name: 'base',
        description: 'This metric reflects the qualities of a vulnerability that are constant over time and across user environments.'
    };

    public static readonly AV = {
        name: 'Attack Vector',
        shortName: 'AV',
        subCategory: 'Exploitability Metrics',
        description: 'This metric reflects the context by which vulnerability exploitation is possible. The more remote an attacker can be to attack a host, the greater the vulnerability score.',
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'N',
                value: 0.85,
                name: 'Network',
                abbreviatedName: 'Netw.',
                jsonSchemaName: 'NETWORK',
                description: 'The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet.'
            },
            {
                shortName: 'A',
                value: 0.62,
                name: 'Adjacent Network',
                abbreviatedName: 'Adj. Network',
                jsonSchemaName: 'ADJACENT_NETWORK',
                description: 'The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.'
            },
            {
                shortName: 'L',
                value: 0.55,
                name: 'Local',
                jsonSchemaName: 'LOCAL',
                description: 'The vulnerable component is not bound to the network stack and the attacker\'s path is via read/write/execute capabilities.'
            },
            {
                shortName: 'P',
                value: 0.2,
                name: 'Physical',
                abbreviatedName: 'Phys.',
                jsonSchemaName: 'PHYSICAL',
                description: 'The attack requires the attacker to physically touch or manipulate the vulnerable component.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly AC = {
        name: 'Attack Complexity',
        shortName: 'AC',
        subCategory: 'Exploitability Metrics',
        description: 'This metric describes the conditions beyond the attacker\'s control that must exist in order to exploit the vulnerability.',
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'L',
                value: 0.77,
                name: 'Low',
                jsonSchemaName: 'LOW',
                description: 'Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.'
            },
            {
                shortName: 'H',
                value: 0.44,
                name: 'High',
                jsonSchemaName: 'HIGH',
                description: 'A successful attack depends on conditions beyond the attacker\'s control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly PR = {
        name: 'Privileges Required',
        shortName: 'PR',
        subCategory: 'Exploitability Metrics',
        description: 'This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.',
        values: [
            {
                shortName: 'X',
                value: 1.0,
                changedValue: 1.0,
                name: 'Not Defined', abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'N',
                value: 0.85,
                changedValue: 0.85,
                name: 'None',
                jsonSchemaName: 'NONE',
                description: 'The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.'
            },
            {
                shortName: 'L',
                value: 0.62,
                changedValue: 0.68,
                name: 'Low',
                jsonSchemaName: 'LOW',
                description: 'The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.'
            },
            {
                shortName: 'H',
                value: 0.27,
                changedValue: 0.5,
                name: 'High',
                jsonSchemaName: 'HIGH',
                description: 'The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.'
            }
        ] as ChangedNumberVectorComponentValue[]
    };

    public static readonly UI = {
        name: 'User Interaction',
        shortName: 'UI',
        subCategory: 'Exploitability Metrics',
        description: 'This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component.',
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'N',
                value: 0.85,
                name: 'None',
                jsonSchemaName: 'NONE',
                description: 'The vulnerable system can be exploited without interaction from any user.'
            },
            {
                shortName: 'R',
                value: 0.62,
                name: 'Required',
                abbreviatedName: 'Req.',
                jsonSchemaName: 'REQUIRED',
                description: 'Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly S = {
        name: 'Scope',
        shortName: 'S',
        subCategory: 'Exploitability Metrics',
        description: 'Can an exploit of the vulnerability be accomplished remotely?',
        values: [
            {
                shortName: 'X',
                value: false,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'U',
                value: false,
                name: 'Unchanged',
                abbreviatedName: 'Unchang.',
                jsonSchemaName: 'UNCHANGED',
                description: 'An exploited vulnerability can only affect resources managed by the same authority.'
            },
            {
                shortName: 'C',
                value: true,
                name: 'Changed',
                jsonSchemaName: 'CHANGED',
                description: 'An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable system\'s design.'
            }
        ] as BooleanVectorComponentValue[]
    };

    public static readonly C = {
        name: 'Confidentiality Impact',
        shortName: 'C',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability.',
        values: Cvss3P1Components.CONFIDENTIALITY_IMPACT
    };

    public static readonly I = {
        name: 'Integrity Impact',
        shortName: 'I',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to integrity of a successfully exploited vulnerability.',
        values: Cvss3P1Components.INTEGRITY_IMPACT
    };

    public static readonly A = {
        name: 'Availability Impact',
        shortName: 'A',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability.',
        values: Cvss3P1Components.AVAILABILITY_IMPACT
    };

    public static readonly BASE_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.AV, this.AC, this.PR, this.UI, this.S, this.C, this.I, this.A
    ];

    public static readonly TEMPORAL_CATEGORY: ComponentCategory = {
        name: 'temporal',
        description: 'This metric reflects the current state of exploit techniques or code availability.',
    };

    public static readonly E = {
        name: 'Exploit Code Maturity',
        shortName: 'E',
        description: 'This metric measures the likelihood of the vulnerability being attacked, and is typically based on the current state of exploit techniques, exploit code availability, or active, successful exploitation of the vulnerability.',
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'U',
                value: 0.91,
                name: 'Unproven',
                abbreviatedName: 'Unproven',
                description: 'No exploit code is available, or an exploit is theoretical.'
            },
            {
                shortName: 'P',
                value: 0.94,
                name: 'Proof-of-Concept',
                abbreviatedName: 'Proof-of-conc.',
                jsonSchemaName: 'PROOF_OF_CONCEPT',
                description: 'Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.'
            },
            {
                shortName: 'F',
                value: 0.97,
                name: 'Functional',
                jsonSchemaName: 'FUNCTIONAL',
                description: 'Functional exploit code is available. The code works in most situations where the vulnerability exists.'
            },
            {
                shortName: 'H',
                value: 1.0,
                name: 'High',
                jsonSchemaName: 'HIGH',
                description: 'Functional exploit code is available. The code is widespread and automated and works in all situations where the vulnerability exists.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly RL = {
        name: 'Remediation Level',
        shortName: 'RL',
        description: 'This metric describes the remediation level for a vulnerability in an affected resource.',
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'O',
                value: 0.95,
                name: 'Official Fix',
                abbreviatedName: 'Off. Fix',
                jsonSchemaName: 'OFFICIAL_FIX',
                description: 'A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.'
            },
            {
                shortName: 'T',
                value: 0.96,
                name: 'Temporary Fix',
                abbreviatedName: 'Temp. Fix',
                jsonSchemaName: 'TEMPORARY_FIX',
                description: 'There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.'
            },
            {
                shortName: 'W',
                value: 0.97,
                name: 'Workaround',
                jsonSchemaName: 'WORKAROUND',
                description: 'There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.'
            },
            {
                shortName: 'U',
                value: 1.0,
                name: 'Unavailable',
                jsonSchemaName: 'UNAVAILABLE',
                description: 'There is either no solution available or it is impossible to apply.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly RC = {
        name: 'Report Confidence',
        shortName: 'RC',
        description: 'This metric describes the level of confidence in the existence of the vulnerability and the credibility of the known technical details.',
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {shortName: 'U', value: 0.92, name: 'Unknown', description: 'Report confidence is unknown.'},
            {
                shortName: 'R',
                value: 0.96,
                name: 'Reasonable',
                jsonSchemaName: 'REASONABLE',
                description: 'Reasonable confidence exists, or the reported vulnerability is in a component not typically used by a target or not having a large installed base.'
            },
            {
                shortName: 'C',
                value: 1.0,
                name: 'Confirmed',
                jsonSchemaName: 'CONFIRMED',
                description: 'Confirmed confidence exists, or the exploit is functional in the environment where the vulnerability exists.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly TEMPORAL_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.E, this.RL, this.RC
    ];

    public static readonly ENVIRONMENTAL_CATEGORY: ComponentCategory = {
        name: 'environmental',
        description: 'This metric reflects the characteristics of a vulnerability that are relevant and unique to a particular user\'s environment. This metric can greatly improve the accuracy of a score.'
    };

    public static readonly MAV = {
        name: 'Modified Attack Vector',
        shortName: 'MAV',
        subCategory: 'Exploitability Metrics',
        description: 'This metric reflects the context by which vulnerability exploitation is possible. The more remote an attacker can be to attack a host, the greater the vulnerability score.',
        baseMetricEquivalent: Cvss3P1Components.AV,
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'N',
                value: 0.85,
                name: 'Network',
                jsonSchemaName: 'NETWORK',
                description: 'The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet.'
            },
            {
                shortName: 'A',
                value: 0.62,
                name: 'Adjacent Network',
                abbreviatedName: 'Adj. Network',
                jsonSchemaName: 'ADJACENT_NETWORK',
                description: 'The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.'
            },
            {
                shortName: 'L',
                value: 0.55,
                name: 'Local',
                jsonSchemaName: 'LOCAL',
                description: 'The vulnerable component is not bound to the network stack and the attacker\'s path is via read/write/execute capabilities.'
            },
            {
                shortName: 'P',
                value: 0.2,
                name: 'Physical',
                jsonSchemaName: 'PHYSICAL',
                description: 'The attack requires the attacker to physically touch or manipulate the vulnerable component.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly MAC = {
        name: 'Modified Attack Complexity',
        shortName: 'MAC',
        subCategory: 'Exploitability Metrics',
        description: 'This metric describes the conditions beyond the attacker\'s control that must exist in order to exploit the vulnerability.',
        baseMetricEquivalent: Cvss3P1Components.AC,
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'L',
                value: 0.77,
                name: 'Low',
                jsonSchemaName: 'LOW',
                description: 'Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.'
            },
            {
                shortName: 'H',
                value: 0.44,
                name: 'High',
                jsonSchemaName: 'HIGH',
                description: 'A successful attack depends on conditions beyond the attacker\'s control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly MPR = {
        name: 'Modified Privileges Required',
        shortName: 'MPR',
        subCategory: 'Exploitability Metrics',
        description: 'This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.',
        baseMetricEquivalent: Cvss3P1Components.PR,
        values: [
            {
                shortName: 'X',
                value: 1.0,
                changedValue: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'N',
                value: 0.85,
                changedValue: 0.85,
                name: 'None',
                jsonSchemaName: 'NONE',
                description: 'The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.'
            },
            {
                shortName: 'L',
                value: 0.62,
                changedValue: 0.68,
                name: 'Low',
                jsonSchemaName: 'LOW',
                description: 'The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.'
            },
            {
                shortName: 'H',
                value: 0.27,
                changedValue: 0.5,
                name: 'High',
                jsonSchemaName: 'HIGH',
                description: 'The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.'
            }
        ] as ChangedNumberVectorComponentValue[]
    };

    public static readonly MUI = {
        name: 'Modified User Interaction',
        shortName: 'MUI',
        subCategory: 'Exploitability Metrics',
        description: 'This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component.',
        baseMetricEquivalent: Cvss3P1Components.UI,
        values: [
            {
                shortName: 'X',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'N',
                value: 0.85,
                name: 'None',
                jsonSchemaName: 'NONE',
                description: 'The vulnerable system can be exploited without interaction from any user.'
            },
            {
                shortName: 'R',
                value: 0.62,
                name: 'Required',
                jsonSchemaName: 'REQUIRED',
                description: 'Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.'
            }
        ] as NumberVectorComponentValue[]
    };

    public static readonly MS = {
        name: 'Modified Scope',
        shortName: 'MS',
        subCategory: 'Exploitability Metrics',
        description: 'Can an exploit of the vulnerability be accomplished remotely?',
        baseMetricEquivalent: Cvss3P1Components.S,
        values: [
            {
                shortName: 'X',
                value: false,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                jsonSchemaName: 'NOT_DEFINED',
                description: 'Component is not defined.'
            },
            {
                shortName: 'U',
                value: false,
                name: 'Unchanged',
                jsonSchemaName: 'UNCHANGED',
                description: 'An exploited vulnerability can only affect resources managed by the same authority.'
            },
            {
                shortName: 'C',
                value: true,
                name: 'Changed',
                jsonSchemaName: 'CHANGED',
                description: 'An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable system\'s design.'
            }
        ] as BooleanVectorComponentValue[]
    };

    public static readonly MC = {
        name: 'Confidentiality Impact',
        shortName: 'MC',
        subCategory: 'Modified Impact',
        description: 'This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability.',
        baseMetricEquivalent: Cvss3P1Components.C,
        values: Cvss3P1Components.CONFIDENTIALITY_IMPACT
    };

    public static readonly MI = {
        name: 'Integrity Impact',
        shortName: 'MI',
        subCategory: 'Modified Impact',
        description: 'This metric measures the impact to integrity of a successfully exploited vulnerability.',
        baseMetricEquivalent: Cvss3P1Components.I,
        values: Cvss3P1Components.INTEGRITY_IMPACT
    };

    public static readonly MA = {
        name: 'Availability Impact',
        shortName: 'MA',
        subCategory: 'Modified Impact',
        description: 'This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability.',
        baseMetricEquivalent: Cvss3P1Components.A,
        values: Cvss3P1Components.AVAILABILITY_IMPACT
    };

    public static readonly CR = {
        name: 'Confidentiality Requirement',
        shortName: 'CR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric describes the remediation level for a vulnerability in an affected resource.',
        values: Cvss3P1Components.CONFIDENTIALITY_REQUIREMENT
    };

    public static readonly IR = {
        name: 'Integrity Requirement',
        shortName: 'IR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric describes the remediation level for a vulnerability in an affected resource.',
        values: Cvss3P1Components.INTEGRITY_REQUIREMENT
    };

    public static readonly AR = {
        name: 'Availability Requirement',
        shortName: 'AR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric describes the remediation level for a vulnerability in an affected resource.',
        values: Cvss3P1Components.AVAILABILITY_REQUIREMENT
    };

    public static readonly ENVIRONMENTAL_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.MAV, this.MAC, this.MPR, this.MUI, this.MS, this.MC, this.MI, this.MA, this.CR, this.IR, this.AR
    ];

    static readonly REGISTERED_COMPONENTS = new Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>();

    static {
        Cvss3P1Components.REGISTERED_COMPONENTS.set(Cvss3P1Components.BASE_CATEGORY, Cvss3P1Components.BASE_CATEGORY_VALUES);
        Cvss3P1Components.REGISTERED_COMPONENTS.set(Cvss3P1Components.TEMPORAL_CATEGORY, Cvss3P1Components.TEMPORAL_CATEGORY_VALUES);
        Cvss3P1Components.REGISTERED_COMPONENTS.set(Cvss3P1Components.ENVIRONMENTAL_CATEGORY, Cvss3P1Components.ENVIRONMENTAL_CATEGORY_VALUES);
    }
}
