<script setup lang="ts">
import { computed } from 'vue'
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

const props = defineProps<{ vector: string }>()

const label = computed(() => {
    const text = props.vector
    if (text.startsWith('CVSS:4.0/')) return new Cvss4P0(text).calculateScores().overall.toFixed(1)
    if (text.startsWith('CVSS:3.1/')) return new Cvss3P1(text).calculateScores().overall.toFixed(1)
    if (text.startsWith('CVSS:3.0/')) return new Cvss3P0(text).calculateScores().overall.toFixed(1)
    return new Cvss2(text).calculateScores().overall.toFixed(1)
})
</script>

<template>
    <strong>{{ label }}</strong>
</template>
