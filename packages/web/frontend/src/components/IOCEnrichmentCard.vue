<script setup lang="ts">
import { computed } from 'vue'
import Card from 'primevue/card'
import Tag from 'primevue/tag'
import ProgressBar from 'primevue/progressbar'

const props = defineProps<{
  provider: string
  riskScore: number | null
  tags: string[]
  confidence: number
  fetchedAt: string | null
  isStale: boolean
}>()

const scoreColor = computed(() => {
  const s = props.riskScore ?? 0
  if (s > 70) return 'danger'
  if (s > 40) return 'warn'
  return 'success'
})
</script>

<template>
  <Card class="enrichment-card">
    <template #title>{{ provider }}</template>
    <template #content>
      <div v-if="riskScore !== null" class="mb-3">
        <div class="flex justify-between items-center mb-1">
          <span class="text-sm">Risk Score</span>
          <span class="font-bold">{{ riskScore }}/100</span>
        </div>
        <ProgressBar :value="riskScore" :showValue="false" />
      </div>
      <div v-else class="text-sm text-surface-500 mb-3">No score available</div>

      <div class="flex flex-wrap gap-1 mb-2">
        <Tag v-for="tag in tags" :key="tag" :value="tag" severity="secondary" />
      </div>

      <div class="text-xs text-surface-500">
        Confidence: {{ (confidence * 100).toFixed(0) }}%
        <span v-if="isStale" class="ml-2 text-yellow-500">● stale</span>
      </div>
    </template>
  </Card>
</template>
