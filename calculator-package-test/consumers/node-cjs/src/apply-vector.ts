import { Cvss3P0, Cvss4P0 } from "ae-cvss-calculator";

export interface SeverityEntry {
  kind: "v3" | "v4";
  vector: string;
}

export interface ScoreSummary {
  v3: string | null;
  v4: string | null;
}

function applyAndScore(target: Cvss3P0 | Cvss4P0, vector: string): string | null {
  try {
    target.applyVector(vector);
    return target.calculateScores().overall.toString();
  } catch {
    return null;
  }
}

export function summarizeScores(entries: SeverityEntry[]): ScoreSummary {
  const v3Entry = entries.find((entry) => entry.kind === "v3");
  const v4Entry = entries.find((entry) => entry.kind === "v4");
  return {
    v3: v3Entry ? applyAndScore(new Cvss3P0(), v3Entry.vector) : null,
    v4: v4Entry ? applyAndScore(new Cvss4P0(), v4Entry.vector) : null,
  };
}
