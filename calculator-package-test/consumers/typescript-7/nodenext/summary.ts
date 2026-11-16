import type { CvssVector } from 'ae-cvss-calculator';
import calculator from 'ae-cvss-calculator';

interface JsonSummary {
  baseScore?: number;
  baseSeverity?: string;
}

export interface Summary {
  score: string;
  severity: string;
}

export function summarize(vector: string): Summary | null {
  try {
    const parsed: CvssVector<any> | null | undefined = calculator.fromVector(vector);
    const json = parsed?.createJsonSchema() as JsonSummary | undefined;
    if (json?.baseScore === undefined) {
      return null;
    }
    return {
      score: json.baseScore.toFixed(1),
      severity: (json.baseSeverity ?? 'NONE').toUpperCase(),
    };
  } catch {
    return null;
  }
}
