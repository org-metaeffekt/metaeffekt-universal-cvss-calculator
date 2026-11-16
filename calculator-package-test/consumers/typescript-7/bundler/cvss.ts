import { fromVector } from "ae-cvss-calculator";

export type Version = "2.0" | "3.0" | "3.1" | "4.0";

interface Parsed {
    getVectorName(): string;
    calculateScores(normalize?: boolean): { overall?: number; base?: number };
}

const KNOWN_VERSIONS: readonly Version[] = ["2.0", "3.0", "3.1", "4.0"];

function tryParse(text: string): Parsed | null {
    try {
        return (fromVector(text) as Parsed | undefined) ?? null;
    } catch {
        return null;
    }
}

export function versionOf(text: string): Version | null {
    const name = tryParse(text)?.getVectorName().replace("CVSS:", "");
    return KNOWN_VERSIONS.find((version) => version === name) ?? null;
}

export function normalizedOverall(text: string): number | null {
    return tryParse(text)?.calculateScores(true).overall ?? null;
}
