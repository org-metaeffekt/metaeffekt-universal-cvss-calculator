import { baseScore } from '@/lib/cvss'
import { ClientScore } from './client-score'

export default function Page() {
  const score = baseScore('3.1', [
    ['AV', 'N'], ['AC', 'L'], ['PR', 'N'], ['UI', 'N'],
    ['S', 'U'], ['C', 'H'], ['I', 'H'], ['A', 'H'],
  ])
  return (
    <main>
      <p>{`server-score:${score}`}</p>
      <ClientScore />
    </main>
  )
}
