type Factory = (vector: string) => { calculateScores(): { overall?: unknown } } | undefined;

const CANDIDATES = ["ae-cvss-calculator", "./vendor/ae-cvss-calculator.cjs"];

function resolveFactory(): Factory {
  for (const candidate of CANDIDATES) {
    try {
      return (require(candidate) as { fromVector: Factory }).fromVector;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "MODULE_NOT_FOUND") {
        throw error;
      }
    }
  }
  throw new Error("No CVSS calculator available");
}

const factory = resolveFactory();

export function overallOf(vector: string): number {
  const overall = factory(vector)?.calculateScores().overall;
  if (typeof overall !== "number") {
    throw new Error(`Cannot score ${vector}`);
  }
  return overall;
}
