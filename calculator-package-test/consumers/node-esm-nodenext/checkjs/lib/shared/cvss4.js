import calculator from 'ae-cvss-calculator'

const { Cvss4P0 } = calculator

/** @type {[number, string][]} */
const BANDS = [
  [9, 'CRITICAL'],
  [7, 'HIGH'],
  [4, 'MEDIUM'],
  [0.1, 'LOW'],
]

/**
 * @param {import('ae-cvss-calculator').Cvss4P0} vector
 * @returns {{ value: number, rating: string }}
 */
function describe(vector) {
  const value = vector.calculateScores().overall
  const band = BANDS.find(([lower]) => value >= lower)
  return { value, rating: band ? band[1] : 'NONE' }
}

/**
 * @param {string} text
 * @returns {{ value: number, rating: string }}
 */
export function rateCvss40(text) {
  return describe(new Cvss4P0(text))
}
