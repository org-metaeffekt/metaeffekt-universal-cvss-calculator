import { rateAdvisories } from './routes/vulnerabilities.ts'

export default {
  async fetch(request: Request): Promise<Response> {
    const vector = new URL(request.url).searchParams.get('vector') ?? ''
    return Response.json(rateAdvisories([{ id: 'ADVISORY-1', vector }]))
  },
}
