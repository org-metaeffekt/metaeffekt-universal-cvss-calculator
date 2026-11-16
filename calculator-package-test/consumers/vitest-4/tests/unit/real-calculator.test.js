import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ScoreBadge from '@/components/ScoreBadge.vue'

describe('ScoreBadge with the real calculator', () => {
  it('renders the base score of a CVSS 4.0 vector', async () => {
    const wrapper = mount(ScoreBadge)
    wrapper.vm.score('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H')
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toBe('5.9')
  })
})
