<!-- packages/web/frontend/src/components/QueryResultsPane.vue -->
<template>
  <div class="query-results">
    <div v-if="loading" class="loading">Running query...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else-if="result" class="results-grid">
      <div class="stats">
        {{ result.stats.rows_returned }} rows, {{ result.stats.duration_ms.toFixed(1) }}ms
        <span v-if="result.truncated" class="truncated">(truncated)</span>
      </div>
      <table v-if="result.rows.length > 0">
        <thead>
          <tr>
            <th v-for="col in result.columns" :key="col">{{ col }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, idx) in result.rows" :key="idx" @click="$emit('row-click', row, idx)">
            <td v-for="col in result.columns" :key="col">{{ formatCell(row[col]) }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="no-results">No results</div>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  result: any | null
  loading: boolean
  error: string | null
}>()

defineEmits<{
  'row-click': [row: any, index: number]
}>()

function formatCell(value: any): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
</script>

<style scoped>
.query-results { overflow: auto; }
.stats { padding: 8px 12px; font-size: 0.85em; color: var(--p-surface-400); }
.truncated { color: var(--p-orange-400); }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 6px 10px; border-bottom: 1px solid var(--p-surface-700, #333); text-align: left; font-size: 13px; }
th { font-weight: 600; background: var(--p-surface-800, #1e1e2e); position: sticky; top: 0; color: var(--p-surface-200); }
tr:hover { background: var(--p-surface-800, #1e1e2e); cursor: pointer; }
.error { color: var(--p-red-400); padding: 8px; }
.loading { padding: 8px; color: var(--p-surface-400); }
.no-results { padding: 12px; color: var(--p-surface-500); text-align: center; }
</style>
