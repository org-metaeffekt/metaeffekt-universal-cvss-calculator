<script setup lang="ts">
import { computed } from 'vue'
import { makeScorer, type Version } from '@/scorer'

const props = defineProps<{ version: Version; vector: string }>()

const overall = computed(() => makeScorer(props.version, props.vector).calculateScores().overall)
</script>

<template>
    <em>{{ overall }}</em>
</template>
