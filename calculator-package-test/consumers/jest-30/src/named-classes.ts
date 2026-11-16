import { Cvss4P0, Cvss3P1 } from "ae-cvss-calculator";

export function severityToNumber(value: string): number | null {
  if (/^\d+(\.\d+)?$/.test(value)) {
    const numeric = Number(value);
    return numeric <= 10 ? numeric : null;
  }
  try {
    if (value.startsWith("CVSS:4.0/")) {
      return new Cvss4P0(value).calculateScores().overall;
    }
    if (value.startsWith("CVSS:3.1/")) {
      return new Cvss3P1(value).calculateScores().overall;
    }
    return null;
  } catch {
    return null;
  }
}
