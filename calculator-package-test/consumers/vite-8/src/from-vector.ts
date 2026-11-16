import { fromVector } from 'ae-cvss-calculator'

export interface MetricLine {
  metric: string
  value: string
}

export function definedMetrics(vector: string): MetricLine[] {
  const parsed = fromVector(vector)
  const lines: MetricLine[] = []
  for (const [component, value] of parsed.getComponents()) {
    if (value.shortName !== 'X' && value.shortName !== 'ND') {
      lines.push({ metric: component.name, value: value.name })
    }
  }
  return lines
}

export function heading(vector: string, label: string): string {
  const parsed = fromVector(vector)
  return `${parsed.getVectorName()} ${label} ${parsed.calculateScores().overall.toFixed(1)}`
}
