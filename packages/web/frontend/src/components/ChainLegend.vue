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
  <div class="legend-bar">
    <div class="legend-items">
      <div v-for="s in severities" :key="s.label" class="legend-item">
        <span class="legend-dot" :style="{ backgroundColor: s.color }"></span>
        <Tag :value="s.label" :style="{ background: s.color + '22', color: s.color, border: 'none', fontSize: '11px', padding: '2px 6px' }" />
      </div>
      <span class="legend-divider">|</span>
      <div class="legend-item">
        <span class="legend-line" style="background: var(--p-surface-300, #ccc);"></span>
        <span class="legend-text">Confirmed</span>
      </div>
      <div class="legend-item">
        <span class="legend-line" style="background: var(--p-surface-500, #888); border-top: 2px dashed var(--p-surface-500, #888); height: 0;"></span>
        <span class="legend-text" style="color: var(--p-surface-400);">Candidate</span>
      </div>
    </div>
    <div class="legend-count">
      Showing {{ renderedCount }} of {{ totalCount }}
    </div>
  </div>
</template>

<style scoped>
.legend-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 16px;
  border-top: 1px solid var(--p-surface-700, #333);
  font-size: 13px;
}
.legend-items {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}
.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}
.legend-line {
  width: 20px;
  height: 2px;
  display: inline-block;
}
.legend-divider {
  color: var(--p-surface-500);
  margin: 0 4px;
}
.legend-text {
  font-size: 12px;
  color: var(--p-surface-300);
}
.legend-count {
  font-size: 12px;
  color: var(--p-surface-500);
}
</style>
