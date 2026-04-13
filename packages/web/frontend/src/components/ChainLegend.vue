<script setup lang="ts">
defineProps<{
  renderedCount: number
  totalCount: number
}>()

const severities = [
  { label: 'Critical', color: '#e74c3c' },
  { label: 'High', color: '#e67e22' },
  { label: 'Medium', color: '#f1c40f' },
  { label: 'Low', color: '#3498db' },
  { label: 'Info', color: '#95a5a6' },
]
</script>

<template>
  <div class="flex items-center justify-between px-4 py-2 border-t border-surface-200 dark:border-surface-700 text-sm">
    <div class="flex items-center gap-4">
      <div v-for="s in severities" :key="s.label" class="flex items-center gap-1">
        <span class="inline-block w-3 h-3 rounded-full" :style="{ backgroundColor: s.color }" />
        <span>{{ s.label }}</span>
      </div>
      <span class="text-surface-400 mx-1">|</span>
      <span>── Confirmed</span>
      <span>╌╌ Candidate</span>
    </div>
    <div class="text-surface-500">
      Showing {{ renderedCount }} of {{ totalCount }}
    </div>
  </div>
</template>
