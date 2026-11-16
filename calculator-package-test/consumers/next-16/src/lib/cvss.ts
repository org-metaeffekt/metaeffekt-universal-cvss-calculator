import { Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

export type Version = '3.1' | '4.0'

export type MetricPairs = [string, string][]

export function composeVector(version: Version, pairs: MetricPairs): string {
  return [`CVSS:${version}`, ...pairs.map(([key, value]) => `${key}:${value}`)].join('/')
}

export function baseScore(version: Version, pairs: MetricPairs): number | null {
  const vector = composeVector(version, pairs)
  try {
    const instance = version === '4.0' ? new Cvss4P0(vector) : new Cvss3P1(vector)
    if (!instance.isBaseFullyDefined()) {
      return null
    }
    return instance.calculateScores().base ?? null
  } catch {
    return null
  }
}
