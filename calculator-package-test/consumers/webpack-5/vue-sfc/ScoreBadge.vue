<template>
  <span>{{ summary ? summary.baseScore : '' }}</span>
</template>

<script>
import { Cvss4P0 } from 'ae-cvss-calculator'

export default {
  name: 'ScoreBadge',
  data() {
    return {
      summary: null
    }
  },
  methods: {
    score(text) {
      this.summary = new Cvss4P0(text).createJsonSchema()
      return this.summary
    }
  }
}
</script>
