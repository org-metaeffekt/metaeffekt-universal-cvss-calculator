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
import { ComponentCategory, CvssVector, VectorComponent, VectorComponentValue } from "../CvssVector";

export class Cvss4P0Components {

    public static readonly VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of confidentiality, resulting in all information within the Vulnerable System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Vulnerable System.'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no loss of confidentiality within the Vulnerable System.'
        }
    };

    public static readonly VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE = [
        Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.X,
        Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.H,
        Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.L,
        Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.N
    ] as VectorComponentValue[];

    public static readonly VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Vulnerable System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Vulnerable System.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Vulnerable System.'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no loss of integrity within the Vulnerable System.'
        }
    };

    public static readonly VULNERABLE_SYSTEM_INTEGRITY_BASE = [
        Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.X,
        Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.H,
        Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.L,
        Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.N
    ] as VectorComponentValue[];

    public static readonly VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Vulnerable System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Vulnerable System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Vulnerable System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Vulnerable System.'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no impact to availability within the Vulnerable System.'
        }
    };

    public static readonly VULNERABLE_SYSTEM_AVAILABILITY_BASE = [
        Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.X,
        Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.H,
        Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.L,
        Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.N
    ] as VectorComponentValue[];

    public static readonly SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        S: {
            shortName: 'S',
            name: 'Safety',
            jsonSchemaName: 'SAFETY',
            description: '! NOT A VALID VALUE FOR Safety (S), REQUIRED FOR CALCULATION OF SCORE !',
            hide: true
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of confidentiality, resulting in all resources within the Subsequent System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Subsequent System.'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no loss of confidentiality within the Subsequent System or all confidentiality impact is constrained to the Vulnerable System.'
        }
    };

    public static readonly SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE = [
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.X,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.S,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.H,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.L,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.N
    ] as VectorComponentValue[];

    public static readonly SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        S: {
            shortName: 'S',
            name: 'Safety',
            jsonSchemaName: 'SAFETY',
            description: '! NOT A VALID VALUE FOR Safety (S), REQUIRED FOR CALCULATION OF SCORE !',
            hide: true
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Subsequent System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Subsequent System.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Subsequent System.'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no loss of integrity within the Subsequent System or all integrity impact is constrained to the Vulnerable System.'
        }
    };

    public static readonly SUBSEQUENT_SYSTEM_INTEGRITY_BASE = [
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.X,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.S,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.H,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.L,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.N
    ] as VectorComponentValue[];

    public static readonly SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        S: {
            shortName: 'S',
            name: 'Safety',
            jsonSchemaName: 'SAFETY',
            description: '! NOT A VALID VALUE FOR Safety (S), REQUIRED FOR CALCULATION OF SCORE !',
            hide: true
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Subsequent System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Subsequent System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Subsequent System.'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'There is no impact to availability within the Subsequent System or all availability impact is constrained to the Vulnerable System.'
        }
    };

    public static readonly SUBSEQUENT_SYSTEM_AVAILABILITY_BASE = [
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.X,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.S,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.H,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.L,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.N
    ] as VectorComponentValue[];

    // SUBSEQUENT SYSTEM MODIFIED

    public static readonly SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of confidentiality, resulting in all resources within the Subsequent System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Subsequent System.'
        },
        N: {
            shortName: 'N',
            name: 'Negligible',
            abbreviatedName: 'Negl.',
            jsonSchemaName: 'NEGLIGIBLE',
            description: 'There is no loss of confidentiality within the Subsequent System or all confidentiality impact is constrained to the Vulnerable System.'
        },
    };

    private static readonly SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED = [
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.X,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.H,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.L,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.N
    ] as VectorComponentValue[];

    public static readonly SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        S: {
            shortName: 'S',
            name: 'Safety',
            jsonSchemaName: 'SAFETY',
            description: 'The exploited vulnerability will result in integrity impacts that could cause serious injury or worse (categories of "Marginal" or worse as described in IEC 61508) to a human actor or participant.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Subsequent System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Subsequent System.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Subsequent System.'
        },
        N: {
            shortName: 'N',
            name: 'Negligible',
            abbreviatedName: 'Negl.',
            jsonSchemaName: 'NEGLIGIBLE',
            description: 'There is no loss of integrity within the Subsequent System or all integrity impact is constrained to the Vulnerable System.'
        }
    };

    private static readonly SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED = [
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.X,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.S,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.H,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.L,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.N
    ] as VectorComponentValue[];

    public static readonly SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        S: {
            shortName: 'S',
            name: 'Safety',
            jsonSchemaName: 'SAFETY',
            description: 'The exploited vulnerability will result in availability impacts that could cause serious injury or worse (categories of "Marginal" or worse as described in IEC 61508) to a human actor or participant.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Subsequent System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Subsequent System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Subsequent System.'
        },
        N: {
            shortName: 'N',
            name: 'Negligible',
            abbreviatedName: 'Negl.',
            jsonSchemaName: 'NEGLIGIBLE',
            description: 'There is no impact to availability within the Subsequent System or all availability impact is constrained to the Vulnerable System.'
        }
    };

    private static readonly SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED = [
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.X,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.S,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.H,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.L,
        Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.N
    ] as VectorComponentValue[];

    // REQUIREMENT

    public static readonly REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        M: {
            shortName: 'M',
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of Confidentiality is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    };

    public static readonly REQUIREMENT_CONFIDENTIALITY_MODIFIED = [
        Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.X,
        Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.H,
        Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.M,
        Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.L
    ] as VectorComponentValue[];

    public static readonly REQUIREMENT_INTEGRITY_MODIFIED_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        M: {
            shortName: 'M',
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of Integrity is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    };

    public static readonly REQUIREMENT_INTEGRITY_MODIFIED = [
        Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.X,
        Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.H,
        Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.M,
        Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.L
    ] as VectorComponentValue[];

    public static readonly REQUIREMENT_AVAILABILITY_MODIFIED_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Component is not defined.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'Loss of Availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        M: {
            shortName: 'M',
            name: 'Medium',
            jsonSchemaName: 'MEDIUM',
            description: 'Loss of Availability is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'Loss of Availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
        }
    };

    public static readonly REQUIREMENT_AVAILABILITY_MODIFIED = [
        Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.X,
        Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.H,
        Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.M,
        Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.L
    ] as VectorComponentValue[];

    /* base metrics */

    public static readonly AV_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Not Defined'
        },
        N: {
            shortName: 'N',
            name: 'Network',
            jsonSchemaName: 'NETWORK',
            description: 'The vulnerable system is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers). An example of a network attack is an attacker causing a denial of service (DoS) by sending a specially crafted TCP packet across a wide area network.'
        },
        A: {
            shortName: 'A',
            name: 'Adjacent Network',
            abbreviatedName: 'Adj. Network',
            jsonSchemaName: 'ADJACENT',
            description: 'The vulnerable system is bound to a protocol stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared proximity (e.g., Bluetooth, NFC, or IEEE 802.11) or logical network (e.g., local IP subnet), or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN within an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment.'
        },
        L: {
            shortName: 'L',
            name: 'Local',
            jsonSchemaName: 'LOCAL',
            description: 'The vulnerable system is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or through terminal emulation (e.g., SSH); or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).'
        },
        P: {
            shortName: 'P',
            name: 'Physical',
            abbreviatedName: 'Phys.',
            jsonSchemaName: 'PHYSICAL',
            description: 'The attack requires the attacker to physically touch or manipulate the vulnerable system. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA).'
        }
    };

    public static readonly AV = {
        name: 'Attack Vector',
        shortName: 'AV',
        subCategory: 'Exploitability Metrics',
        description: 'This metric reflects the context by which vulnerability exploitation is possible.',
        values: [
            Cvss4P0Components.AV_VALUES.X,
            Cvss4P0Components.AV_VALUES.N,
            Cvss4P0Components.AV_VALUES.A,
            Cvss4P0Components.AV_VALUES.L,
            Cvss4P0Components.AV_VALUES.P
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.AV_VALUES.N
    };

    public static readonly AC_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Not Defined'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention to exploit the vulnerability. An attacker can expect repeatable success against the vulnerable system.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'successful attack depends on the evasion or circumvention of security-enhancing techniques in place that would otherwise hinder the attack. The attacker must have additional methods available to bypass security measures in place.'
        }
    };

    public static readonly AC = {
        name: 'Attack Complexity',
        shortName: 'AC',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: [
            Cvss4P0Components.AC_VALUES.X,
            Cvss4P0Components.AC_VALUES.L,
            Cvss4P0Components.AC_VALUES.H
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.AC_VALUES.L
    };

    public static readonly AT_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Not Defined'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'The successful attack does not depend on the deployment and execution conditions of the vulnerable system. The attacker can expect to be able to reach the vulnerability and execute the exploit under all or most instances of the vulnerability.'
        },
        P: {
            shortName: 'P',
            name: 'Present',
            jsonSchemaName: 'PRESENT',
            description: 'The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable system that enable the attack. The successfulness of the attack is conditioned on execution conditions that are not under full control of the attacker. The attack may need to be launched multiple times against a single target before being successful. Network injection. The attacker must inject themselves into the logical network path between the target and the resource requested by the victim (e.g. vulnerabilities requiring an on-path attacker).'
        }
    };

    public static readonly AT = {
        name: 'Attack Requirements',
        shortName: 'AT',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: [
            Cvss4P0Components.AT_VALUES.X,
            Cvss4P0Components.AT_VALUES.N,
            Cvss4P0Components.AT_VALUES.P
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.AT_VALUES.N
    };

    public static readonly PR_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Not Defined'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'The attacker is unauthenticated prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'The attacker requires privileges that provide basic capabilities that are typically limited to settings and resources owned by a single low-privileged user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable system allowing full access to the vulnerable system’s settings and files.'
        }
    };

    public static readonly PR = {
        name: 'Privileges Required',
        shortName: 'PR',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: [
            Cvss4P0Components.PR_VALUES.X,
            Cvss4P0Components.PR_VALUES.N,
            Cvss4P0Components.PR_VALUES.L,
            Cvss4P0Components.PR_VALUES.H
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.PR_VALUES.N
    };

    public static readonly UI_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Not Defined'
        },
        N: {
            shortName: 'N',
            name: 'None',
            jsonSchemaName: 'NONE',
            description: 'The vulnerable system can be exploited without interaction from any human user, other than the attacker. Examples include: a remote attacker is able to send packets to a target system a locally authenticated attacker executes code to elevate privileges'
        },
        P: {
            shortName: 'P',
            name: 'Passive',
            jsonSchemaName: 'PASSIVE',
            description: 'Successful exploitation of this vulnerability requires limited interaction by the targeted user with the vulnerable system and the attacker’s payload. These interactions would be considered involuntary and do not require that the user actively subvert protections built into the vulnerable system.'
        },
        A: {
            shortName: 'A',
            name: 'Active',
            jsonSchemaName: 'ACTIVE',
            description: 'Successful exploitation of this vulnerability requires a targeted user to perform specific, conscious interactions with the vulnerable system and the attacker’s payload, or the user’s interactions would actively subvert protection mechanisms which would lead to exploitation of the vulnerability.'
        }
    };

    public static readonly UI = {
        name: 'User Interaction',
        shortName: 'UI',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: [
            Cvss4P0Components.UI_VALUES.X,
            Cvss4P0Components.UI_VALUES.N,
            Cvss4P0Components.UI_VALUES.P,
            Cvss4P0Components.UI_VALUES.A
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.UI_VALUES.N
    };

    public static readonly VC = {
        name: 'Confidentiality',
        shortName: 'VC',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE,
        worseCaseValue: Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.H
    };

    public static readonly VI = {
        name: 'Integrity',
        shortName: 'VI',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE,
        worseCaseValue: Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.H
    };

    public static readonly VA = {
        name: 'Availability',
        shortName: 'VA',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE,
        worseCaseValue: Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.H
    };

    public static readonly SC = {
        name: 'Confidentiality',
        shortName: 'SC',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE,
        worseCaseValue: Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.H
    };

    public static readonly SI = {
        name: 'Integrity',
        shortName: 'SI',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE,
        worseCaseValue: Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.H
    };

    public static readonly SA = {
        name: 'Availability',
        shortName: 'SA',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE,
        worseCaseValue: Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.H
    };

    /* supplemental metrics */

    public static readonly S_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'The metric has not been evaluated.'
        },
        N: {
            shortName: 'N',
            name: 'Negligible',
            abbreviatedName: 'Negl.',
            jsonSchemaName: 'NEGLIGIBLE',
            description: 'Consequences of the vulnerability meet definition of IEC 61508 consequence categories of "marginal," "critical," or "catastrophic."'
        },
        P: {
            shortName: 'P',
            name: 'Present',
            jsonSchemaName: 'PRESENT',
            description: 'Consequences of the vulnerability meet definition of IEC 61508 consequence category "negligible."'
        }
    };

    public static readonly S = {
        name: 'Safety',
        shortName: 'S',
        description: '',
        values: [
            Cvss4P0Components.S_VALUES.X,
            Cvss4P0Components.S_VALUES.N,
            Cvss4P0Components.S_VALUES.P
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.S_VALUES.P
    };

    public static readonly AU_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'The metric has not been evaluated.'
        },
        N: {
            shortName: 'N',
            name: 'No',
            jsonSchemaName: 'NO',
            description: 'Attackers cannot reliably automate all 4 steps of the kill chain for this vulnerability for some reason. These steps are reconnaissance, weaponization, delivery, and exploitation.'
        },
        Y: {
            shortName: 'Y',
            name: 'Yes',
            jsonSchemaName: 'YES',
            description: 'Attackers can reliably automate all 4 steps of the kill chain. These steps are reconnaissance, weaponization, delivery, and exploitation (e.g., the vulnerability is “wormable”).'
        }
    };

    public static readonly AU = {
        name: 'Automated',
        shortName: 'AU',
        description: '',
        values: [
            Cvss4P0Components.AU_VALUES.X,
            Cvss4P0Components.AU_VALUES.N,
            Cvss4P0Components.AU_VALUES.Y
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.AU_VALUES.Y
    };

    public static readonly R_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'The metric has not been evaluated.'
        },
        A: {
            shortName: 'A',
            name: 'Automatic',
            abbreviatedName: 'Automat.',
            jsonSchemaName: 'AUTOMATIC',
            description: 'The system recovers services automatically after an attack has been performed.'
        },
        U: {
            shortName: 'U',
            name: 'User',
            jsonSchemaName: 'USER',
            description: 'The system requires manual intervention by the user to recover services, after an attack has been performed.'
        },
        I: {
            shortName: 'I',
            name: 'Irrecoverable',
            abbreviatedName: 'Irrecov.',
            jsonSchemaName: 'IRRECOVERABLE',
            description: 'The system services are irrecoverable by the user, after an attack has been performed.'
        }
    };

    public static readonly R = {
        name: 'Recovery',
        shortName: 'R',
        description: '',
        values: [
            Cvss4P0Components.R_VALUES.X,
            Cvss4P0Components.R_VALUES.A,
            Cvss4P0Components.R_VALUES.U,
            Cvss4P0Components.R_VALUES.I
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.R_VALUES.I
    };

    public static readonly V_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'The metric has not been evaluated.'
        },
        D: {
            shortName: 'D',
            name: 'Diffuse',
            jsonSchemaName: 'DIFFUSE',
            description: 'The vulnerable system has limited resources. That is, the resources that the attacker will gain control over with a single exploitation event are relatively small. An example of Diffuse (think: limited) Value Density would be an attack on a single email client vulnerability.'
        },
        C: {
            shortName: 'C',
            name: 'Concentrated',
            abbreviatedName: 'Concentr.',
            jsonSchemaName: 'CONCENTRATED',
            description: 'The vulnerable system is rich in resources. Heuristically, such systems are often the direct responsibility of “system operators” rather than users. An example of Concentrated (think: broad) Value Density would be an attack on a central email server.'
        }
    };

    public static readonly V = {
        name: 'Value Density',
        shortName: 'V',
        description: '',
        values: [
            Cvss4P0Components.V_VALUES.X,
            Cvss4P0Components.V_VALUES.D,
            Cvss4P0Components.V_VALUES.C
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.V_VALUES.C
    };

    public static readonly RE_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'The metric has not been evaluated.'
        },
        L: {
            shortName: 'L',
            name: 'Low',
            jsonSchemaName: 'LOW',
            description: 'The effort required to respond to a vulnerability is low/trivial. Examples include: communication on better documentation, configuration workarounds, or guidance from the vendor that does not require an immediate update, upgrade, or replacement by the consuming entity, such as firewall filter configuration.'
        },
        M: {
            shortName: 'M',
            name: 'Moderate',
            abbreviatedName: 'Moder.',
            jsonSchemaName: 'MODERATE',
            description: 'The actions required to respond to a vulnerability require some effort on behalf of the consumer and could cause minimal service impact to implement. Examples include: simple remote update, disabling of a subsystem, or a low-touch software upgrade such as a driver update.'
        },
        H: {
            shortName: 'H',
            name: 'High',
            jsonSchemaName: 'HIGH',
            description: 'The actions required to respond to a vulnerability are significant and/or difficult, and may possibly lead to an extended, scheduled service impact. This would need to be considered for scheduling purposes including honoring any embargo on deployment of the selected response. Alternatively, response to the vulnerability in the field is not possible remotely. The only resolution to the vulnerability involves physical replacement (e.g. units deployed would have to be recalled for a depot level repair or replacement).'
        }
    };

    public static readonly RE = {
        name: 'Vulnerability Response Effort',
        shortName: 'RE',
        description: '',
        values: [
            Cvss4P0Components.RE_VALUES.X,
            Cvss4P0Components.RE_VALUES.L,
            Cvss4P0Components.RE_VALUES.M,
            Cvss4P0Components.RE_VALUES.H
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.RE_VALUES.H
    };

    public static readonly U_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'The metric has not been evaluated.'
        },
        Clear: {
            shortName: 'Clear',
            name: 'Clear',
            jsonSchemaName: 'CLEAR',
            description: 'Provider has assessed the impact of this vulnerability as having the highest urgency.'
        },
        Green: {
            shortName: 'Green',
            name: 'Green',
            jsonSchemaName: 'GREEN',
            description: 'Provider has assessed the impact of this vulnerability as having a moderate urgency.'
        },
        Amber: {
            shortName: 'Amber',
            name: 'Amber',
            jsonSchemaName: 'AMBER',
            description: 'Provider has assessed the impact of this vulnerability as having a reduced urgency.'
        },
        Red: {
            shortName: 'Red',
            name: 'Red',
            jsonSchemaName: 'RED',
            description: 'Provider has assessed the impact of this vulnerability as having no urgency (Informational).'
        }
    };

    public static readonly U = {
        name: 'Provider Urgency',
        shortName: 'U',
        description: '',
        values: [
            Cvss4P0Components.U_VALUES.X,
            Cvss4P0Components.U_VALUES.Clear,
            Cvss4P0Components.U_VALUES.Green,
            Cvss4P0Components.U_VALUES.Amber,
            Cvss4P0Components.U_VALUES.Red
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.U_VALUES.Red
    };

    /* environmental metrics */

    public static readonly MAV = {
        name: 'Modified Attack Vector',
        shortName: 'MAV',
        subCategory: 'Exploitability Metrics',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.AV,
        values: Cvss4P0Components.AV.values,
        worseCaseValue: Cvss4P0Components.AV_VALUES.N
    };

    public static readonly MAC = {
        name: 'Modified Attack Complexity',
        shortName: 'MAC',
        subCategory: 'Exploitability Metrics',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.AC,
        values: Cvss4P0Components.AC.values,
        worseCaseValue: Cvss4P0Components.AC_VALUES.L
    };

    public static readonly MAT = {
        name: 'Modified Attack Requirements',
        shortName: 'MAT',
        subCategory: 'Exploitability Metrics',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.AT,
        values: Cvss4P0Components.AT.values,
        worseCaseValue: Cvss4P0Components.AT_VALUES.P
    };

    public static readonly MPR = {
        name: 'Modified Privileges Required',
        shortName: 'MPR',
        subCategory: 'Exploitability Metrics',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.PR,
        values: Cvss4P0Components.PR.values,
        worseCaseValue: Cvss4P0Components.PR_VALUES.N
    };

    public static readonly MUI = {
        name: 'Modified User Interaction',
        shortName: 'MUI',
        subCategory: 'Exploitability Metrics',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.UI,
        values: Cvss4P0Components.UI.values,
        worseCaseValue: Cvss4P0Components.UI_VALUES.N
    };

    public static readonly MVC = {
        name: 'Modified Confidentiality',
        shortName: 'MVC',
        subCategory: 'Vulnerable System Impact',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.VC,
        values: Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE,
        worseCaseValue: Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.H
    };

    public static readonly MVI = {
        name: 'Modified Integrity',
        shortName: 'MVI',
        subCategory: 'Vulnerable System Impact',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.VI,
        values: Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE,
        worseCaseValue: Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.H
    };

    public static readonly MVA = {
        name: 'Modified Availability',
        shortName: 'MVA',
        subCategory: 'Vulnerable System Impact',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.VA,
        values: Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE,
        worseCaseValue: Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.H
    };

    public static readonly MSC = {
        name: 'Modified Confidentiality',
        shortName: 'MSC',
        subCategory: 'Subsequent System Impact',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.SC,
        values: Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED,
        worseCaseValue: Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.H
    };

    public static readonly MSI = {
        name: 'Modified Integrity',
        shortName: 'MSI',
        subCategory: 'Subsequent System Impact',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.SI,
        baseMetricEquivalentMapper: (value: VectorComponentValue) => {
            if (value === Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.S) {
                return Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.H;
            }
            return value;
        },
        values: Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED,
        worseCaseValue: Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.H
    };

    public static readonly MSA = {
        name: 'Modified Availability',
        shortName: 'MSA',
        subCategory: 'Subsequent System Impact',
        description: '',
        baseMetricEquivalent: Cvss4P0Components.SA,
        baseMetricEquivalentMapper: (value: VectorComponentValue) => {
            if (value === Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.S) {
                return Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.H;
            }
            return value;
        },
        values: Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED,
        worseCaseValue: Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.H
    };

    public static readonly CR = {
        name: 'Confidentiality Requirement',
        shortName: 'CR',
        description: '',
        values: Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED,
        worseCaseValue: Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.H
    };

    public static readonly IR = {
        name: 'Integrity Requirement',
        shortName: 'IR',
        description: '',
        values: Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED,
        worseCaseValue: Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.H
    };

    public static readonly AR = {
        name: 'Availability Requirement',
        shortName: 'AR',
        description: '',
        values: Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED,
        worseCaseValue: Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.H
    };

    public static readonly E_VALUES = {
        X: {
            shortName: 'X',
            name: 'Not Defined',
            abbreviatedName: 'Not Def.',
            jsonSchemaName: 'NOT_DEFINED',
            description: 'Reliable threat intelligence is not available to determine Exploit Maturity characteristics. This is the default value and is equivalent to Attacked (A) for the purposes of the calculation of the score by assuming the worst case.'
        },
        A: {
            shortName: 'A',
            name: 'Attacked',
            jsonSchemaName: 'ATTACKED',
            description: 'Based on available threat intelligence either of the following must apply: Attacks targeting this vulnerability (attempted or successful) have been reported Solutions to simplify attempts to exploit the vulnerability are publicly or privately available (such as exploit toolkits)'
        },
        P: {
            shortName: 'P',
            name: 'POC',
            jsonSchemaName: 'PROOF_OF_CONCEPT',
            description: 'Based on available threat intelligence each of the following must apply: Proof-of-concept exploit code is publicly available No knowledge of reported attempts to exploit this vulnerability No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability (i.e., the “Attacked” value does not apply)'
        },
        U: {
            shortName: 'U',
            name: 'Unreported',
            jsonSchemaName: 'UNREPORTED',
            description: 'Based on available threat intelligence each of the following must apply: No knowledge of publicly available proof-of-concept exploit code No knowledge of reported attempts to exploit this vulnerability No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability (i.e., neither the “POC” nor “Attacked” values apply)'
        }
    };

    public static readonly E = {
        name: 'Exploit Maturity',
        shortName: 'E',
        description: '',
        values: [
            Cvss4P0Components.E_VALUES.X,
            Cvss4P0Components.E_VALUES.A,
            Cvss4P0Components.E_VALUES.P,
            Cvss4P0Components.E_VALUES.U
        ] as VectorComponentValue[],
        worseCaseValue: Cvss4P0Components.E_VALUES.A
    };


    public static readonly BASE_CATEGORY: ComponentCategory = {
        name: 'base',
        description: 'Base Metrics'
    };

    public static readonly SUPPLEMENTAL_CATEGORY: ComponentCategory = {
        name: 'supplemental',
        description: 'Supplemental Metrics'
    };

    public static readonly ENVIRONMENTAL_MODIFIED_BASE_CATEGORY: ComponentCategory = {
        name: 'environmental-base',
        description: 'Environmental Metrics (Modified Base)'
    };

    public static readonly ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY: ComponentCategory = {
        name: 'environmental-security-requirement',
        description: 'Environmental Metrics (Security Requirements)'
    };

    public static readonly THREAT_CATEGORY: ComponentCategory = {
        name: 'threat',
        description: 'Threat Metrics'
    };

    public static readonly BASE_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        Cvss4P0Components.AV, Cvss4P0Components.AC, Cvss4P0Components.AT, Cvss4P0Components.PR, Cvss4P0Components.UI,
        Cvss4P0Components.VC, Cvss4P0Components.VI, Cvss4P0Components.VA,
        Cvss4P0Components.SC, Cvss4P0Components.SI, Cvss4P0Components.SA
    ];

    public static readonly SUPPLEMENTAL_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        Cvss4P0Components.S, Cvss4P0Components.AU, Cvss4P0Components.R, Cvss4P0Components.V, Cvss4P0Components.RE, Cvss4P0Components.U
    ];

    public static readonly ENVIRONMENTAL_MODIFIED_BASE_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        Cvss4P0Components.MAV, Cvss4P0Components.MAC, Cvss4P0Components.MAT, Cvss4P0Components.MPR, Cvss4P0Components.MUI,
        Cvss4P0Components.MVC, Cvss4P0Components.MVI, Cvss4P0Components.MVA,
        Cvss4P0Components.MSC, Cvss4P0Components.MSI, Cvss4P0Components.MSA
    ];

    public static readonly ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        Cvss4P0Components.CR, Cvss4P0Components.IR, Cvss4P0Components.AR
    ];

    public static readonly THREAT_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        Cvss4P0Components.E
    ];

    static readonly REGISTERED_COMPONENTS_EDITOR_ORDER = new Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>();
    static readonly REGISTERED_COMPONENTS_VECTOR_STRING_ORDER = new Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>();

    static {
        Cvss4P0Components.REGISTERED_COMPONENTS_EDITOR_ORDER.set(Cvss4P0Components.BASE_CATEGORY, Cvss4P0Components.BASE_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_EDITOR_ORDER.set(Cvss4P0Components.SUPPLEMENTAL_CATEGORY, Cvss4P0Components.SUPPLEMENTAL_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_EDITOR_ORDER.set(Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY, Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_EDITOR_ORDER.set(Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY, Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_EDITOR_ORDER.set(Cvss4P0Components.THREAT_CATEGORY, Cvss4P0Components.THREAT_CATEGORY_VALUES);

        // AV AC AT PR UI VC VI VA SC SI SA E CR IR AR MAV MAC MAT MPR MUI MVC MVI MVA MSC MSI MSA S AU R V RE U
        Cvss4P0Components.REGISTERED_COMPONENTS_VECTOR_STRING_ORDER.set(Cvss4P0Components.BASE_CATEGORY, Cvss4P0Components.BASE_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_VECTOR_STRING_ORDER.set(Cvss4P0Components.THREAT_CATEGORY, Cvss4P0Components.THREAT_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_VECTOR_STRING_ORDER.set(Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY, Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_VECTOR_STRING_ORDER.set(Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY, Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS_VECTOR_STRING_ORDER.set(Cvss4P0Components.SUPPLEMENTAL_CATEGORY, Cvss4P0Components.SUPPLEMENTAL_CATEGORY_VALUES);
    }

    static readonly MV_LOOKUP: Record<string, number> = {
        "000000": 10,
        "000001": 9.9,
        "000010": 9.8,
        "000011": 9.5,
        "000020": 9.5,
        "000021": 9.2,
        "000100": 10,
        "000101": 9.6,
        "000110": 9.3,
        "000111": 8.7,
        "000120": 9.1,
        "000121": 8.1,
        "000200": 9.3,
        "000201": 9,
        "000210": 8.9,
        "000211": 8,
        "000220": 8.1,
        "000221": 6.8,
        "001000": 9.8,
        "001001": 9.5,
        "001010": 9.5,
        "001011": 9.2,
        "001020": 9,
        "001021": 8.4,
        "001100": 9.3,
        "001101": 9.2,
        "001110": 8.9,
        "001111": 8.1,
        "001120": 8.1,
        "001121": 6.5,
        "001200": 8.8,
        "001201": 8,
        "001210": 7.8,
        "001211": 7,
        "001220": 6.9,
        "001221": 4.8,
        "002001": 9.2,
        "002011": 8.2,
        "002021": 7.2,
        "002101": 7.9,
        "002111": 6.9,
        "002121": 5,
        "002201": 6.9,
        "002211": 5.5,
        "002221": 2.7,
        "010000": 9.9,
        "010001": 9.7,
        "010010": 9.5,
        "010011": 9.2,
        "010020": 9.2,
        "010021": 8.5,
        "010100": 9.5,
        "010101": 9.1,
        "010110": 9,
        "010111": 8.3,
        "010120": 8.4,
        "010121": 7.1,
        "010200": 9.2,
        "010201": 8.1,
        "010210": 8.2,
        "010211": 7.1,
        "010220": 7.2,
        "010221": 5.3,
        "011000": 9.5,
        "011001": 9.3,
        "011010": 9.2,
        "011011": 8.5,
        "011020": 8.5,
        "011021": 7.3,
        "011100": 9.2,
        "011101": 8.2,
        "011110": 8,
        "011111": 7.2,
        "011120": 7,
        "011121": 5.9,
        "011200": 8.4,
        "011201": 7,
        "011210": 7.1,
        "011211": 5.2,
        "011220": 5,
        "011221": 3,
        "012001": 8.6,
        "012011": 7.5,
        "012021": 5.2,
        "012101": 7.1,
        "012111": 5.2,
        "012121": 2.9,
        "012201": 6.3,
        "012211": 2.9,
        "012221": 1.7,
        "100000": 9.8,
        "100001": 9.5,
        "100010": 9.4,
        "100011": 8.7,
        "100020": 9.1,
        "100021": 8.1,
        "100100": 9.4,
        "100101": 8.9,
        "100110": 8.6,
        "100111": 7.4,
        "100120": 7.7,
        "100121": 6.4,
        "100200": 8.7,
        "100201": 7.5,
        "100210": 7.4,
        "100211": 6.3,
        "100220": 6.3,
        "100221": 4.9,
        "101000": 9.4,
        "101001": 8.9,
        "101010": 8.8,
        "101011": 7.7,
        "101020": 7.6,
        "101021": 6.7,
        "101100": 8.6,
        "101101": 7.6,
        "101110": 7.4,
        "101111": 5.8,
        "101120": 5.9,
        "101121": 5,
        "101200": 7.2,
        "101201": 5.7,
        "101210": 5.7,
        "101211": 5.2,
        "101220": 5.2,
        "101221": 2.5,
        "102001": 8.3,
        "102011": 7,
        "102021": 5.4,
        "102101": 6.5,
        "102111": 5.8,
        "102121": 2.6,
        "102201": 5.3,
        "102211": 2.1,
        "102221": 1.3,
        "110000": 9.5,
        "110001": 9,
        "110010": 8.8,
        "110011": 7.6,
        "110020": 7.6,
        "110021": 7,
        "110100": 9,
        "110101": 7.7,
        "110110": 7.5,
        "110111": 6.2,
        "110120": 6.1,
        "110121": 5.3,
        "110200": 7.7,
        "110201": 6.6,
        "110210": 6.8,
        "110211": 5.9,
        "110220": 5.2,
        "110221": 3,
        "111000": 8.9,
        "111001": 7.8,
        "111010": 7.6,
        "111011": 6.7,
        "111020": 6.2,
        "111021": 5.8,
        "111100": 7.4,
        "111101": 5.9,
        "111110": 5.7,
        "111111": 5.7,
        "111120": 4.7,
        "111121": 2.3,
        "111200": 6.1,
        "111201": 5.2,
        "111210": 5.7,
        "111211": 2.9,
        "111220": 2.4,
        "111221": 1.6,
        "112001": 7.1,
        "112011": 5.9,
        "112021": 3,
        "112101": 5.8,
        "112111": 2.6,
        "112121": 1.5,
        "112201": 2.3,
        "112211": 1.3,
        "112221": 0.6,
        "200000": 9.3,
        "200001": 8.7,
        "200010": 8.6,
        "200011": 7.2,
        "200020": 7.5,
        "200021": 5.8,
        "200100": 8.6,
        "200101": 7.4,
        "200110": 7.4,
        "200111": 6.1,
        "200120": 5.6,
        "200121": 3.4,
        "200200": 7,
        "200201": 5.4,
        "200210": 5.2,
        "200211": 4,
        "200220": 4,
        "200221": 2.2,
        "201000": 8.5,
        "201001": 7.5,
        "201010": 7.4,
        "201011": 5.5,
        "201020": 6.2,
        "201021": 5.1,
        "201100": 7.2,
        "201101": 5.7,
        "201110": 5.5,
        "201111": 4.1,
        "201120": 4.6,
        "201121": 1.9,
        "201200": 5.3,
        "201201": 3.6,
        "201210": 3.4,
        "201211": 1.9,
        "201220": 1.9,
        "201221": 0.8,
        "202001": 6.4,
        "202011": 5.1,
        "202021": 2,
        "202101": 4.7,
        "202111": 2.1,
        "202121": 1.1,
        "202201": 2.4,
        "202211": 0.9,
        "202221": 0.4,
        "210000": 8.8,
        "210001": 7.5,
        "210010": 7.3,
        "210011": 5.3,
        "210020": 6,
        "210021": 5,
        "210100": 7.3,
        "210101": 5.5,
        "210110": 5.9,
        "210111": 4,
        "210120": 4.1,
        "210121": 2,
        "210200": 5.4,
        "210201": 4.3,
        "210210": 4.5,
        "210211": 2.2,
        "210220": 2,
        "210221": 1.1,
        "211000": 7.5,
        "211001": 5.5,
        "211010": 5.8,
        "211011": 4.5,
        "211020": 4,
        "211021": 2.1,
        "211100": 6.1,
        "211101": 5.1,
        "211110": 4.8,
        "211111": 1.8,
        "211120": 2,
        "211121": 0.9,
        "211200": 4.6,
        "211201": 1.8,
        "211210": 1.7,
        "211211": 0.7,
        "211220": 0.8,
        "211221": 0.2,
        "212001": 5.3,
        "212011": 2.4,
        "212021": 1.4,
        "212101": 2.4,
        "212111": 1.2,
        "212121": 0.5,
        "212201": 1,
        "212211": 0.3,
        "212221": 0.1
    };

    public static readonly ATTRIBUTE_SEVERITY_ORDER: VectorComponentValue[][] = [
        // AttackRequirements
        [Cvss4P0Components.AT_VALUES.P, Cvss4P0Components.AT_VALUES.P],
        [Cvss4P0Components.AT_VALUES.N, Cvss4P0Components.AT_VALUES.N],
        [Cvss4P0Components.AT_VALUES.X, Cvss4P0Components.AT_VALUES.X],

        // Safety
        [Cvss4P0Components.S_VALUES.X],
        [Cvss4P0Components.S_VALUES.N],
        [Cvss4P0Components.S_VALUES.P],

        // Automatable
        [Cvss4P0Components.AU_VALUES.X],
        [Cvss4P0Components.AU_VALUES.N],
        [Cvss4P0Components.AU_VALUES.Y],

        // ValueDensity
        [Cvss4P0Components.V_VALUES.X],
        [Cvss4P0Components.V_VALUES.D],
        [Cvss4P0Components.V_VALUES.C],

        // AttackComplexity
        [Cvss4P0Components.AC_VALUES.H, Cvss4P0Components.AC_VALUES.H],
        [Cvss4P0Components.AC_VALUES.L, Cvss4P0Components.AC_VALUES.L],
        [Cvss4P0Components.AC_VALUES.X, Cvss4P0Components.AC_VALUES.X],

        // PrivilegesRequired
        [Cvss4P0Components.PR_VALUES.H, Cvss4P0Components.PR_VALUES.H],
        [Cvss4P0Components.PR_VALUES.L, Cvss4P0Components.PR_VALUES.L],
        [Cvss4P0Components.PR_VALUES.N, Cvss4P0Components.PR_VALUES.N],
        [Cvss4P0Components.PR_VALUES.X, Cvss4P0Components.PR_VALUES.X],

        // UserInteraction
        [Cvss4P0Components.UI_VALUES.A, Cvss4P0Components.UI_VALUES.A],
        [Cvss4P0Components.UI_VALUES.P, Cvss4P0Components.UI_VALUES.P],
        [Cvss4P0Components.UI_VALUES.N, Cvss4P0Components.UI_VALUES.N],
        [Cvss4P0Components.UI_VALUES.X, Cvss4P0Components.UI_VALUES.X],

        // VulnerabilityCia
        [Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.X, Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.X, Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.X],
        [Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.N, Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.N, Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.N],
        [Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.L, Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.L, Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.L],
        [Cvss4P0Components.VULNERABLE_SYSTEM_CONFIDENTIALITY_BASE_VALUES.H, Cvss4P0Components.VULNERABLE_SYSTEM_INTEGRITY_BASE_VALUES.H, Cvss4P0Components.VULNERABLE_SYSTEM_AVAILABILITY_BASE_VALUES.H],

        // Subsequent CIA metrics
        [
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.X,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.X,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.X,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.X,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.X,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.X
        ],
        [
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.N,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.N,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.N,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.N,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.N,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.N
        ],
        [
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.L,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.L,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.L,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.L,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.L,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.L
        ],
        [
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_MODIFIED_VALUES.H,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.H,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.H,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.H,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.H,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.H
        ],
        [
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.S,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.S,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_CONFIDENTIALITY_BASE_VALUES.S,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_BASE_VALUES.S,
            Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_BASE_VALUES.S
        ],

        // RequirementsCia
        [Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.L, Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.L, Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.L],
        [Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.M, Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.M, Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.M],
        [Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.H, Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.H, Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.H],
        [Cvss4P0Components.REQUIREMENT_CONFIDENTIALITY_MODIFIED_VALUES.X, Cvss4P0Components.REQUIREMENT_AVAILABILITY_MODIFIED_VALUES.X, Cvss4P0Components.REQUIREMENT_INTEGRITY_MODIFIED_VALUES.X],

        // ExploitMaturity
        [Cvss4P0Components.E_VALUES.U],
        [Cvss4P0Components.E_VALUES.P],
        [Cvss4P0Components.E_VALUES.A],
        [Cvss4P0Components.E_VALUES.X],

        // Recovery
        [Cvss4P0Components.R_VALUES.X],
        [Cvss4P0Components.R_VALUES.A],
        [Cvss4P0Components.R_VALUES.U],
        [Cvss4P0Components.R_VALUES.I],

        // VulnerabilityResponseEffort
        [Cvss4P0Components.RE_VALUES.X],
        [Cvss4P0Components.RE_VALUES.L],
        [Cvss4P0Components.RE_VALUES.M],
        [Cvss4P0Components.RE_VALUES.H],

        // ProviderUrgency
        [Cvss4P0Components.U_VALUES.X],
        [Cvss4P0Components.U_VALUES.Clear],
        [Cvss4P0Components.U_VALUES.Green],
        [Cvss4P0Components.U_VALUES.Amber],
        [Cvss4P0Components.U_VALUES.Red],

        // AttackVector
        [Cvss4P0Components.AV_VALUES.X, Cvss4P0Components.AV_VALUES.X],
        [Cvss4P0Components.AV_VALUES.P, Cvss4P0Components.AV_VALUES.P],
        [Cvss4P0Components.AV_VALUES.L, Cvss4P0Components.AV_VALUES.L],
        [Cvss4P0Components.AV_VALUES.A, Cvss4P0Components.AV_VALUES.A],
        [Cvss4P0Components.AV_VALUES.N, Cvss4P0Components.AV_VALUES.N]
    ];
}