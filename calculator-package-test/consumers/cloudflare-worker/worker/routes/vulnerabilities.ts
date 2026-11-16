import { fromVector } from 'ae-cvss-calculator'

export interface Advisory {
  id: string
  vector: string
}

export interface RatedAdvisory {
  id: string
  score: number | null
}

export function rateAdvisories(advisories: Advisory[]): RatedAdvisory[] {
  return advisories.map(({ id, vector }) => ({
    id,
    score: fromVector(vector)?.calculateScores().overall ?? null,
  }))
}
