import calculator from 'ae-cvss-calculator'

const { Cvss4P0 } = calculator

const BANDS = [
  [9, 'CRITICAL'],
  [7, 'HIGH'],
  [4, 'MEDIUM'],
  [0.1, 'LOW'],
]

export function rateCvss40(text) {
  const value = new Cvss4P0(text).calculateScores().overall
  const band = BANDS.find(([lower]) => value >= lower)
  return { value, rating: band ? band[1] : 'NONE' }
}
