'use client'

import { useMemo } from 'react'
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

const SAMPLE_VECTORS = [
  'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H',
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  'AV:N/AC:L/Au:N/C:P/I:P/A:P',
]

function baseFor(vector: string): number | null {
  try {
    if (vector.startsWith('CVSS:4.0/')) return new Cvss4P0(vector).calculateScores().base ?? null
    if (vector.startsWith('CVSS:3.1/')) return new Cvss3P1(vector).calculateScores().base ?? null
    if (vector.startsWith('CVSS:3.0/')) return new Cvss3P0(vector).calculateScores().base ?? null
    return new Cvss2(vector).calculateScores().base ?? null
  } catch {
    return null
  }
}

export function ScoreList() {
  const scores = useMemo(() => SAMPLE_VECTORS.map(baseFor), [])
  return <p>{`scores:${scores.join(',')}`}</p>
}
