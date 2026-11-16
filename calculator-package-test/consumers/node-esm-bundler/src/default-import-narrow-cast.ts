import calculator from "ae-cvss-calculator";

type ExactScorer = new (vector: string) => { calculateExactOverallScore(): number };
type OverallScorer = new (vector: string) => { calculateOverallScore(): number };

const { Cvss3P0, Cvss4P0 } = calculator as { Cvss3P0: ExactScorer; Cvss4P0: OverallScorer };

export function scoreAdvisory(kind: "v3" | "v4", vector: string): string | null {
    try {
        const value = kind === "v3"
            ? new Cvss3P0(vector).calculateExactOverallScore()
            : new Cvss4P0(vector).calculateOverallScore();
        return String(value);
    } catch {
        return null;
    }
}
