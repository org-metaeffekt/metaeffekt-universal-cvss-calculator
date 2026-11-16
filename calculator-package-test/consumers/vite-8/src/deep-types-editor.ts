import { Cvss3P1, Cvss4P0 } from "ae-cvss-calculator";
import {
    ComponentCategory,
    type VectorComponent,
    type VectorComponentValue,
} from "ae-cvss-calculator/dist/types/src/CvssVector";
import {
    CriticalSeverityType,
    HighSeverityType,
    LowSeverityType,
    MediumSeverityType,
    NoneSeverityType,
} from "ae-cvss-calculator/dist/types/src/cvss4p0/Cvss4P0";

export type EditableVector = Cvss3P1 | Cvss4P0;

type Severity =
    | NoneSeverityType
    | LowSeverityType
    | MediumSeverityType
    | HighSeverityType
    | CriticalSeverityType;

export const SEVERITY_ORDER: Record<Severity, number> = {
    NONE: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
};

export interface CategoryEntry {
    category: ComponentCategory;
    components: VectorComponent<VectorComponentValue>[];
}

export function vectorFromText(text: string): EditableVector | null {
    const factories: [string, () => EditableVector][] = [
        ["CVSS:3.1/", () => new Cvss3P1(text)],
        ["CVSS:4.0/", () => new Cvss4P0(text)],
    ];
    const match = factories.find(([prefix]) => text.startsWith(prefix));
    return match ? match[1]() : null;
}

export function emptyVector(version: "3.1" | "4.0"): EditableVector {
    if (version === "4.0") {
        return new Cvss4P0();
    }
    return new Cvss3P1();
}

export function categoriesOf(vector: EditableVector): CategoryEntry[] {
    return [...vector.getRegisteredComponents()].map(([category, components]) => ({ category, components }));
}

export function isVersion4(vector: EditableVector | null): vector is Cvss4P0 {
    return vector instanceof Cvss4P0;
}
