<script setup lang="ts">
import Tag from 'primevue/tag'

defineProps<{
  renderedCount: number
  totalCount: number
}>()

const severities = [
  { label: 'Critical', color: '#e74c3c', severity: 'danger' },
  { label: 'High', color: '#e67e22', severity: 'warn' },
  { label: 'Medium', color: '#f1c40f', severity: 'warn' },
  { label: 'Low', color: '#3498db', severity: 'info' },
  { label: 'Info', color: '#95a5a6', severity: 'secondary' },
]
</script>

<template>
  <div class="flex items-center justify-between px-4 py-2 border-t border-surface-700 text-sm">
    <div class="flex items-center gap-3 flex-wrap">
      <div v-for="s in severities" :key="s.label" class="flex items-center gap-1">
        <span class="inline-block w-3 h-3 rounded-full" :style="{ backgroundColor: s.color }" />
        <Tag :value="s.label" :style="{ background: s.color + '22', color: s.color, border: 'none', fontSize: '11px', padding: '2px 6px' }" />
      </div>
      <span class="text-surface-500 mx-2">|</span>
      <span class="flex items-center gap-1">
        <span style="width: 20px; height: 2px; background: var(--p-surface-300); display: inline-block;"></span>
        <span class="text-surface-300 text-xs">Confirmed</span>
      </span>
      <span class="flex items-center gap-1">
        <span style="width: 20px; height: 2px; background: var(--p-surface-500); display: inline-block; border-top: 2px dashed var(--p-surface-500); height: 0;"></span>
        <span class="text-surface-400 text-xs">Candidate</span>
      </span>
    </div>
    <div class="text-surface-500 text-xs">
      Showing {{ renderedCount }} of {{ totalCount }}
    </div>
  </div>
</template>
