import {ComponentCategory, VectorComponent, VectorComponentValue} from "../CvssVector";

export class Cvss4P0Components {

    public static readonly TEMPLATE_CIA_BASE_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Component is not defined.'},
        H: {shortName: 'H', name: 'High', description: ''},
        L: {shortName: 'L', name: 'Low', description: ''},
        N: {shortName: 'N', name: 'None', description: ''}
    };

    public static readonly TEMPLATE_CIA_BASE = [
        Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.X,
        Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.H,
        Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.L,
        Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.N
    ] as VectorComponentValue[];

    public static readonly TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Component is not defined.'},
        S: {
            shortName: 'S',
            name: 'Safety',
            description: '! NOT A VALID VALUE FOR Safety (S), REQUIRED FOR CALCULATION OF SCORE !',
            hide: true
        },
        H: {shortName: 'H', name: 'High', description: ''},
        L: {shortName: 'L', name: 'Low', description: ''},
        N: {shortName: 'N', name: 'None', description: ''}
    };

    public static readonly TEMPLATE_CIA_SUBSEQUENT_BASE = [
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.X,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.S,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.H,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.L,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.N
    ] as VectorComponentValue[];

    private static readonly TEMPLATE_CIA_SUBSEQUENT_MODIFIED = [
        {shortName: 'X', name: 'Not Defined', description: 'Component is not defined.'},
        {shortName: 'H', name: 'High', description: ''},
        {shortName: 'L', name: 'Low', description: ''},
        {shortName: 'N', name: 'Negligible', description: ''}
    ] as VectorComponentValue[];

    public static readonly TEMPLATE_CIA_SUBSEQUENT_MODIFIED_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Component is not defined.'},
        H: {shortName: 'H', name: 'High', description: ''},
        L: {shortName: 'L', name: 'Low', description: ''},
        N: {shortName: 'N', name: 'Negligible', description: ''}
    };

    public static readonly TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Component is not defined.'},
        S: {shortName: 'S', name: 'Safety', description: ''},
        H: {shortName: 'H', name: 'High', description: ''},
        L: {shortName: 'L', name: 'Low', description: ''},
        N: {shortName: 'N', name: 'Negligible', description: ''}
    };

    public static readonly TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED = [
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.X,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.S,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.H,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.L,
        Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.N
    ] as VectorComponentValue[]


    public static readonly TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Component is not defined.'},
        H: {shortName: 'H', name: 'High', description: ''},
        M: {shortName: 'M', name: 'Medium', description: ''},
        L: {shortName: 'L', name: 'Low', description: ''}
    };

    public static readonly TEMPLATE_CIA_REQUIREMENT_MODIFIED = [
        Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.X,
        Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.H,
        Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.M,
        Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.L
    ] as VectorComponentValue[];


    /* base metrics */

    public static readonly AV_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        N: {shortName: 'N', name: 'Network', description: ''},
        A: {shortName: 'A', name: 'Adjacent Network', description: ''},
        L: {shortName: 'L', name: 'Local', description: ''},
        P: {shortName: 'P', name: 'Physical', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        L: {shortName: 'L', name: 'Low', description: ''},
        H: {shortName: 'H', name: 'High', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        N: {shortName: 'N', name: 'None', description: ''},
        P: {shortName: 'P', name: 'Present', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        N: {shortName: 'N', name: 'None', description: ''},
        L: {shortName: 'L', name: 'Low', description: ''},
        H: {shortName: 'H', name: 'High', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        N: {shortName: 'N', name: 'None', description: ''},
        P: {shortName: 'P', name: 'Passive', description: ''},
        A: {shortName: 'A', name: 'Active', description: ''}
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
        values: Cvss4P0Components.TEMPLATE_CIA_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.H
    };

    public static readonly VI = {
        name: 'Integrity',
        shortName: 'VI',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.H
    };

    public static readonly VA = {
        name: 'Availability',
        shortName: 'VA',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.H
    };

    public static readonly SC = {
        name: 'Confidentiality',
        shortName: 'SC',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.H
    };

    public static readonly SI = {
        name: 'Integrity',
        shortName: 'SI',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.H
    };

    public static readonly SA = {
        name: 'Availability',
        shortName: 'SA',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_BASE_VALUES.H
    };

    /* supplemental metrics */

    public static readonly S_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        N: {shortName: 'N', name: 'Negligible', description: ''},
        P: {shortName: 'P', name: 'Present', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        N: {shortName: 'N', name: 'No', description: ''},
        Y: {shortName: 'Y', name: 'Yes', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        A: {shortName: 'A', name: 'Automatic', description: ''},
        U: {shortName: 'U', name: 'User', description: ''},
        I: {shortName: 'I', name: 'Irrecoverable', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        D: {shortName: 'D', name: 'Diffuse', description: ''},
        C: {shortName: 'C', name: 'Concentrated', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        L: {shortName: 'L', name: 'Low', description: ''},
        M: {shortName: 'M', name: 'Moderate', description: ''},
        H: {shortName: 'H', name: 'High', description: ''}
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
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        Clear: {shortName: 'Clear', name: 'Clear', description: ''},
        Green: {shortName: 'Green', name: 'Green', description: ''},
        Amber: {shortName: 'Amber', name: 'Amber', description: ''},
        Red: {shortName: 'Red', name: 'Red', description: ''}
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
        values: Cvss4P0Components.AV.values,
        worseCaseValue: Cvss4P0Components.AV_VALUES.N
    };

    public static readonly MAC = {
        name: 'Modified Attack Complexity',
        shortName: 'MAC',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: Cvss4P0Components.AC.values,
        worseCaseValue: Cvss4P0Components.AC_VALUES.L
    };

    public static readonly MAT = {
        name: 'Modified Attack Requirements',
        shortName: 'MAT',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: Cvss4P0Components.AT.values,
        worseCaseValue: Cvss4P0Components.AT_VALUES.P
    };

    public static readonly MPR = {
        name: 'Modified Privileges Required',
        shortName: 'MPR',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: Cvss4P0Components.PR.values,
        worseCaseValue: Cvss4P0Components.PR_VALUES.N
    };

    public static readonly MUI = {
        name: 'Modified User Interaction',
        shortName: 'MUI',
        subCategory: 'Exploitability Metrics',
        description: '',
        values: Cvss4P0Components.UI.values,
        worseCaseValue: Cvss4P0Components.UI_VALUES.N
    };

    public static readonly MVC = {
        name: 'Modified Confidentiality',
        shortName: 'MVC',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.H
    };

    public static readonly MVI = {
        name: 'Modified Integrity',
        shortName: 'MVI',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.H
    };

    public static readonly MVA = {
        name: 'Modified Availability',
        shortName: 'MVA',
        subCategory: 'Vulnerable System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_BASE,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_BASE_VALUES.H
    };

    public static readonly MSC = {
        name: 'Modified Confidentiality',
        shortName: 'MSC',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_MODIFIED,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_MODIFIED_VALUES.H
    };

    public static readonly MSI = {
        name: 'Modified Integrity',
        shortName: 'MSI',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.H
    };

    public static readonly MSA = {
        name: 'Modified Availability',
        shortName: 'MSA',
        subCategory: 'Subsequent System Impact',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.H
    };

    public static readonly CR = {
        name: 'Confidentiality Requirement',
        shortName: 'CR',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.H
    };

    public static readonly IR = {
        name: 'Integrity Requirement',
        shortName: 'IR',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.H
    };

    public static readonly AR = {
        name: 'Availability Requirement',
        shortName: 'AR',
        description: '',
        values: Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED,
        worseCaseValue: Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.H
    };

    public static readonly E_VALUES = {
        X: {shortName: 'X', name: 'Not Defined', description: 'Not Defined'},
        A: {shortName: 'A', name: 'Attacked', description: ''},
        P: {shortName: 'P', name: 'POC', description: ''},
        U: {shortName: 'U', name: 'Unreported', description: ''}
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

    static readonly REGISTERED_COMPONENTS = new Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>();

    static {
        Cvss4P0Components.REGISTERED_COMPONENTS.set(Cvss4P0Components.BASE_CATEGORY, Cvss4P0Components.BASE_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS.set(Cvss4P0Components.SUPPLEMENTAL_CATEGORY, Cvss4P0Components.SUPPLEMENTAL_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS.set(Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY, Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS.set(Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY, Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY_VALUES);
        Cvss4P0Components.REGISTERED_COMPONENTS.set(Cvss4P0Components.THREAT_CATEGORY, Cvss4P0Components.THREAT_CATEGORY_VALUES);
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
}