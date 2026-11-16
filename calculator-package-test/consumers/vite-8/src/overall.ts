import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

export function overallOrNull(vector: string): number | null {
    const text = vector.trim()
    try {
        if (text.startsWith('CVSS:4.0/')) return new Cvss4P0(text).calculateScores(false).overall
        if (text.startsWith('CVSS:3.1/')) return new Cvss3P1(text).calculateScores(false).overall
        if (text.startsWith('CVSS:3.0/')) return new Cvss3P0(text).calculateScores(false).overall
        return new Cvss2(text).calculateScores(false).overall
    } catch {
        return null
    }
}
