import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

export type Version = '2.0' | '3.0' | '3.1' | '4.0'

export interface ScoreSet {
    base?: number
    overall?: number
}

type Scorer = { calculateScores(): ScoreSet }
type ScorerType = new (vector?: string) => Scorer

const TYPES: Record<Version, ScorerType> = {
    '2.0': Cvss2 as unknown as ScorerType,
    '3.0': Cvss3P0 as unknown as ScorerType,
    '3.1': Cvss3P1 as unknown as ScorerType,
    '4.0': Cvss4P0 as unknown as ScorerType,
}

export function makeScorer(version: Version, vector?: string): Scorer {
    const ScorerClass = TYPES[version]
    return vector ? new ScorerClass(vector) : new ScorerClass()
}

export function unwrapVector(text: string): string {
    return text.replace(/^\((.*)\)$/, '$1')
}
