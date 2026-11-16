'use client'

import { useMemo } from 'react'
import { baseScore } from '@/lib/cvss'

export function ClientScore() {
  const score = useMemo(
    () =>
      baseScore('4.0', [
        ['AV', 'P'], ['AC', 'H'], ['AT', 'P'], ['PR', 'H'], ['UI', 'N'], ['VC', 'N'],
        ['VI', 'H'], ['VA', 'H'], ['SC', 'L'], ['SI', 'L'], ['SA', 'H'],
      ]),
    []
  )
  return <p>{`client-score:${score}`}</p>
}
