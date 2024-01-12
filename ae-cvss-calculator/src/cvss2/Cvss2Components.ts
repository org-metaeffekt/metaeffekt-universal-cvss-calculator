import {ComponentCategory, NumberVectorComponentValue, VectorComponent, VectorComponentValue} from "../CvssVector";

export class Cvss2Components {
    public static readonly BASE_CATEGORY: ComponentCategory = {
        name: 'base',
        description: 'Represents the intrinsic and fundamental characteristics of a vulnerability that are constant over time and user environments.'
    };

    public static readonly AV = {
        name: 'Access Vector',
        shortName: 'AV',
        subCategory: 'Exploitability Metrics',
        description: 'This metric reflects how the vulnerability is exploited. The more remote an attacker can be to attack a host, the greater the vulnerability score.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will result in no score being calculated.'
            },
            {
                shortName: 'L',
                value: 0.395,
                name: 'Local',
                description: 'A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. Examples of locally exploitable vulnerabilities are peripheral attacks such as Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo).'
            },
            {
                shortName: 'A',
                value: 0.646,
                name: 'Adjacent Network',
                abbreviatedName: 'Adj. Network',
                description: 'A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.  Examples of local networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.'
            },
            {
                shortName: 'N',
                value: 1.000,
                name: 'Network',
                description: 'A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". An example of a network attack is an RPC buffer overflow.'
            },
        ] as NumberVectorComponentValue[]
    };

    public static readonly AC = {
        name: 'Access Complexity',
        shortName: 'AC',
        subCategory: 'Exploitability Metrics',
        description: 'This metric measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. For example, consider a buffer overflow in an Internet service: If the vulnerability is exploitable only once a user has been authenticated by the service, the vulnerability is only "Medium" complexity. If, however, the vulnerability can be exploited anonymously, it is "Low" complexity.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will result in no score being calculated.'
            },
            {
                shortName: 'H',
                value: 0.35,
                name: 'High',
                description: 'Requires specialized conditions to be present: elevated privileges, system spoofing (e.g., DNS hijacking), easily detected social engineering, or rare configurations. Race conditions, if present, have a very narrow window.'
            },
            {
                shortName: 'M',
                value: 0.61,
                name: 'Medium',
                description: 'The access conditions are somewhat specialized: limited to certain systems/users, requires prior information gathering, non-default configurations, or minor social engineering (e.g., deceptive phishing attacks).'
            },
            {
                shortName: 'L',
                value: 0.71,
                name: 'Low',
                description: 'Specialized access conditions or extenuating circumstances do not exist: wide system/user access (e.g., Internet-facing servers), default configurations, manual attacks requiring little skill, or easily winnable race conditions.'
            },
        ] as NumberVectorComponentValue[]
    };
    public static readonly Au = {
        name: 'Authentication',
        shortName: 'Au',
        subCategory: 'Exploitability Metrics',
        description: 'This metric measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. "Multiple" means that the attacker must authenticate two or more times, "Single" means that the attacker must authenticate once, and "None" means that the attacker need not authenticate at all to exploit the vulnerability.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will result in no score being calculated.'
            },
            {
                shortName: 'M',
                value: 0.45,
                name: 'Multiple',
                description: 'Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. An example is an attacker authenticating to an operating system in addition to providing credentials to access an application hosted on that system.'
            },
            {
                shortName: 'S',
                value: 0.56,
                name: 'Single',
                description: 'The vulnerability requires an attacker to be logged into the system (such as at a command line or via a desktop session or web interface).'
            },
            {
                shortName: 'N',
                value: 0.704,
                name: 'None',
                description: 'Authentication is not required to exploit the vulnerability.'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly C = {
        name: 'Confidentiality Impact',
        shortName: 'C',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will result in no score being calculated.'
            },
            {
                shortName: 'N',
                value: 0.0,
                name: 'None',
                description: 'There is no impact to the confidentiality of the system.'
            },
            {
                shortName: 'P',
                value: 0.275,
                name: 'Partial',
                description: 'There is considerable informational disclosure. Access to some system files is possible, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. An example is a vulnerability that divulges only certain tables in a database.'
            },
            {
                shortName: 'C',
                value: 0.660,
                name: 'Complete',
                description: 'There is total information disclosure, resulting in all system files being revealed. The attacker is able to read all of the system\'s data (memory, files, etc.).'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly I = {
        name: 'Integrity Impact',
        shortName: 'I',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and guaranteed veracity of information.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will result in no score being calculated.'
            },
            {
                shortName: 'N',
                value: 0.0,
                name: 'None',
                description: 'There is no impact to the integrity of the system.'
            },
            {
                shortName: 'P',
                value: 0.275,
                name: 'Partial',
                description: 'Modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited. For example, system or application files may be overwritten or modified, but either the attacker has no control over which files are affected or the attacker can modify files within only a limited context or scope.'
            },
            {
                shortName: 'C',
                value: 0.660,
                name: 'Complete',
                description: 'There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system.'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly A = {
        name: 'Availability Impact',
        shortName: 'A',
        subCategory: 'Impact Metrics',
        description: 'This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the impacted component, this metric refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component. This metric considers only the availability of the impacted component itself.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will result in no score being calculated.'
            },
            {
                shortName: 'N',
                value: 0.0,
                name: 'None',
                description: 'There is no impact to availability within the impacted component.'
            },
            {
                shortName: 'P',
                value: 0.275,
                name: 'Partial',
                description: 'There is reduced performance or interruptions in resource availability. An example is a network-based flood attack that permits a limited number of successful connections to an Internet service.'
            },
            {
                shortName: 'C',
                value: 0.660,
                name: 'Complete',
                description: 'There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable.'
            },
        ] as NumberVectorComponentValue[]
    }

    public static readonly BASE_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.AV, this.AC, this.Au, this.C, this.I, this.A
    ];

    public static readonly TEMPORAL_CATEGORY: ComponentCategory = {
        name: 'temporal',
        description: 'The threat posed by a vulnerability may change over time. Three such factors that CVSS captures are: confirmation of the technical details of a vulnerability, the remediation status of the vulnerability, and the availability of exploit code or techniques. Since temporal metrics are optional they each include a metric value that has no effect on the score.'
    };

    public static readonly E = {
        name: 'Exploitability',
        shortName: 'E',
        description: 'This metric measures the current state of exploit techniques or code availability. "Unproven that exploit exists" is the lowest impact and "Proof-of-concept code" is the highest impact.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {
                shortName: 'U',
                value: 0.85,
                name: 'Unproven',
                description: 'No exploit code is available, or an exploit is entirely theoretical.'
            },
            {
                shortName: 'POC',
                value: 0.9,
                name: 'Proof-of-concept',
                abbreviatedName: 'Proof-of-conc.',
                description: 'Proof-of-concept exploit code or an attack demonstration that is not practical for most systems is available. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.'
            },
            {
                shortName: 'F',
                value: 0.95,
                name: 'Functional',
                description: 'Functional exploit code is available. The code works in most situations where the vulnerability exists.'
            },
            {
                shortName: 'H',
                value: 1.0,
                name: 'High',
                description: 'Either the vulnerability is exploitable by functional mobile autonomous code, or no exploit is required (manual trigger) and details are widely available. The code works in every situation, or is actively being delivered via a mobile autonomous agent (such as a worm or virus).'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly RL = {
        name: 'Remediation Level',
        shortName: 'RL',
        description: 'This metric measures the remediation level of a vulnerability. "Official fix" is the lowest impact and "Unavailable" is the highest impact.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {
                shortName: 'OF',
                value: 0.87,
                name: 'Official Fix',
                abbreviatedName: 'Off. Fix',
                description: 'A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.'
            },
            {
                shortName: 'TF',
                value: 0.9,
                name: 'Temporary Fix',
                abbreviatedName: 'Temp. Fix',
                description: 'There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.'
            },
            {
                shortName: 'W',
                value: 0.95,
                name: 'Workaround',
                description: 'There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.'
            },
            {
                shortName: 'U',
                value: 1.0,
                name: 'Unavailable',
                description: 'There is either no solution available or it is impossible to apply.'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly RC = {
        name: 'Report Confidence',
        shortName: 'RC',
        description: 'This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details. "Unconfirmed" is the lowest confidence and "Confirmed" is the highest.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {
                shortName: 'UC',
                value: 0.9,
                name: 'Unconfirmed',
                description: 'There is little confidence in the existence of this vulnerability. The report is unconfirmed, or the source is not known.'
            },
            {
                shortName: 'UR',
                value: 0.95,
                name: 'Uncorroborated',
                description: 'There is reasonable confidence in the existence of this vulnerability, but the technical details are not known publicly. The report is unconfirmed.'
            },
            {
                shortName: 'C',
                value: 1.0,
                name: 'Confirmed',
                description: 'The existence of this vulnerability is confirmed, but the details are not known publicly. An exploit has been observed, or proof-of-concept exploit code is available. The bugtraq ID or CVE ID has been made public.'
            },
        ] as NumberVectorComponentValue[]
    }

    public static readonly TEMPORAL_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.E, this.RL, this.RC
    ];

    public static readonly ENVIRONMENTAL_CATEGORY: ComponentCategory = {
        name: 'environmental',
        description: 'Different environments can have an immense bearing on the risk that a vulnerability poses to an organization and its stakeholders. The CVSS environmental metric group captures the characteristics of a vulnerability that are associated with a user\'s IT environment. Since environmental metrics are optional they each include a metric value that has no effect on the score.'
    };

    public static readonly CDP = {
        name: 'Collateral Damage Potential',
        shortName: 'CDP',
        subCategory: 'General Modifiers',
        description: 'This metric measures the potential for loss of life or physical assets resulting from a vulnerability. "None" is the lowest impact and "High" is the highest impact.',
        values: [
            {
                shortName: 'ND',
                value: 0.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {
                shortName: 'N',
                value: 0.0,
                name: 'None',
                description: 'There is no potential for loss of life, physical assets, productivity or revenue.'
            },
            {
                shortName: 'L',
                value: 0.1,
                name: 'Low',
                description: 'A successful exploit of this vulnerability may result in slight physical or property damage. Or, there may be a slight loss of revenue or productivity to the organization.'
            },
            {
                shortName: 'LM',
                value: 0.3,
                name: 'Low-Medium',
                abbreviatedName: 'Low-Med.',
                description: 'A successful exploit of this vulnerability may result in moderate physical or property damage. Or, there may be a moderate loss of revenue or productivity to the organization.'
            },
            {
                shortName: 'MH',
                value: 0.4,
                name: 'Medium-High',
                abbreviatedName: 'Med.-High',
                description: 'A successful exploit of this vulnerability may result in significant physical or property damage or loss. Or, there may be a significant loss of revenue or productivity.'
            },
            {
                shortName: 'H',
                value: 0.5,
                name: 'High',
                description: 'A successful exploit of this vulnerability may result in catastrophic physical or property damage and loss. Or, there may be a catastrophic loss of revenue or productivity.'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly TD = {
        name: 'Target Distribution',
        shortName: 'TD',
        subCategory: 'General Modifiers',
        description: 'This metric measures the proportion of vulnerable systems that could be affected by an attack. It is meant to represent the proportion of vulnerable systems that an attacker can expect to target. "None" is the lowest impact and "High" is the highest impact.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {shortName: 'N', value: 0.0, name: 'None', description: 'There is no (0%) target distribution.'},
            {shortName: 'L', value: 0.25, name: 'Low', description: 'There is a small (< 25%) target distribution.'},
            {
                shortName: 'M',
                value: 0.75,
                name: 'Medium',
                description: 'There is a medium (26-75%) target distribution.'
            },
            {shortName: 'H', value: 1.0, name: 'High', description: 'There is a high (> 75%) target distribution.'},
        ] as NumberVectorComponentValue[]
    }
    public static readonly CR = {
        name: 'Confidentiality Requirement',
        shortName: 'CR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric measures the need for confidentiality of the vulnerable component to the user. For example, an attacker that exploits a vulnerability that exists on a network boundary and requires no privileges has a low need for the confidentiality of the vulnerable component. Conversely, an attacker that exploits a vulnerability that exists on the same system as the vulnerable component and requires Privileged access to the system in order to exploit it has a high need for confidentiality. "Not Defined" is the lowest impact and "High" is the highest impact.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {
                shortName: 'L',
                value: 0.5,
                name: 'Low',
                description: 'Loss of confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
            {
                shortName: 'M',
                value: 1.0,
                name: 'Medium',
                description: 'Loss of confidentiality is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
            {
                shortName: 'H',
                value: 1.51,
                name: 'High',
                description: 'Loss of confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly IR = {
        name: 'Integrity Requirement',
        shortName: 'IR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric measures the need for integrity of the vulnerable component to a user. For example, an attacker that exploits a vulnerability that exists on a network boundary and requires no privileges has a low need for the integrity of the vulnerable component. Conversely, an attacker that exploits a vulnerability that exists on the same system as the vulnerable component and requires Privileged access to the system in order to exploit it has a high need for integrity. "Not Defined" is the lowest impact and "High" is the highest impact.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {
                shortName: 'L',
                value: 0.5,
                name: 'Low',
                description: 'Loss of integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
            {
                shortName: 'M',
                value: 1.0,
                name: 'Medium',
                description: 'Loss of integrity is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
            {
                shortName: 'H',
                value: 1.51,
                name: 'High',
                description: 'Loss of integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
        ] as NumberVectorComponentValue[]
    }
    public static readonly AR = {
        name: 'Availability Requirement',
        shortName: 'AR',
        subCategory: 'Modified Requirement (Impact Subscore) Modifiers',
        description: 'This metric measures the need for availability of the vulnerable component to a user. For example, an attacker that exploits a vulnerability that exists on a network boundary and requires no privileges has a low need for the availability of the vulnerable component. Conversely, an attacker that exploits a vulnerability that exists on the same system as the vulnerable component and requires Privileged access to the system in order to exploit it has a high need for availability. "Not Defined" is the lowest impact and "High" is the highest impact.',
        values: [
            {
                shortName: 'ND',
                value: 1.0,
                name: 'Not Defined',
                abbreviatedName: 'Not Def.',
                description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.'
            },
            {
                shortName: 'L',
                value: 0.5,
                name: 'Low',
                description: 'Loss of availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
            {
                shortName: 'M',
                value: 1.0,
                name: 'Medium',
                description: 'Loss of availability is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
            {
                shortName: 'H',
                value: 1.51,
                name: 'High',
                description: 'Loss of availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).'
            },
        ] as NumberVectorComponentValue[]
    }

    public static readonly ENVIRONMENTAL_CATEGORY_VALUES: VectorComponent<VectorComponentValue>[] = [
        this.CDP, this.TD, this.CR, this.IR, this.AR
    ];

    static readonly REGISTERED_COMPONENTS = new Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>();

    static {
        Cvss2Components.REGISTERED_COMPONENTS.set(Cvss2Components.BASE_CATEGORY, Cvss2Components.BASE_CATEGORY_VALUES);
        Cvss2Components.REGISTERED_COMPONENTS.set(Cvss2Components.TEMPORAL_CATEGORY, Cvss2Components.TEMPORAL_CATEGORY_VALUES);
        Cvss2Components.REGISTERED_COMPONENTS.set(Cvss2Components.ENVIRONMENTAL_CATEGORY, Cvss2Components.ENVIRONMENTAL_CATEGORY_VALUES);
    }
}
