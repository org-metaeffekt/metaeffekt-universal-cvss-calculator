import calculator from "ae-cvss-calculator";

export type Label = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Scored {
    score: number;
    label: Label;
}

const BANDS_V3_V4: [number, Label][] = [[9, "CRITICAL"], [7, "HIGH"], [4, "MEDIUM"], [0.1, "LOW"]];
const BANDS_V2: [number, Label][] = [[7, "HIGH"], [4, "MEDIUM"], [0.1, "LOW"]];

function labelFor(score: number, bands: [number, Label][]): Label {
    return bands.find(([minimum]) => score >= minimum)?.[1] ?? "NONE";
}

export function scoreV4(vector: string): Scored | null {
    try {
        const parsed = new calculator.Cvss4P0(vector);
        if (!parsed.isBaseFullyDefined()) return null;
        const score = parsed.calculateScores().baseMetricsOnly;
        if (typeof score !== "number") return null;
        return { score, label: labelFor(score, BANDS_V3_V4) };
    } catch {
        return null;
    }
}

export function scoreV2(vector: string): Scored | null {
    try {
        const parsed = new calculator.Cvss2(vector.replace(/^CVSS:2\.0\//, ""));
        if (!parsed.isBaseFullyDefined()) return null;
        const score = parsed.calculateScores().base;
        if (typeof score !== "number") return null;
        return { score, label: labelFor(score, BANDS_V2) };
    } catch {
        return null;
    }
}
