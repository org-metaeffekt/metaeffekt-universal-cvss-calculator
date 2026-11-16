import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import ScoreBadge from '@/components/ScoreBadge.vue'
import { Cvss4P0 } from 'ae-cvss-calculator'

vi.mock('ae-cvss-calculator', () => ({
  Cvss4P0: vi.fn().mockImplementation(function () {
    this.createJsonSchema = () => ({ baseScore: 8.1 })
  })
}))

describe('ScoreBadge with a mocked calculator', () => {
  afterEach(() => {
    Cvss4P0.mockClear()
  })

  it('renders whatever the mocked class returns', async () => {
    const wrapper = mount(ScoreBadge)
    wrapper.vm.score('any text')
    await wrapper.vm.$nextTick()
    expect(Cvss4P0).toHaveBeenCalledWith('any text')
    expect(wrapper.text()).toBe('8.1')
  })
})
