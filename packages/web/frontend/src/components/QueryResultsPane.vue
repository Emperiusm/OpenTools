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
.stats { padding: 4px 8px; font-size: 0.85em; color: #666; }
.truncated { color: #e67e22; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 6px 8px; border-bottom: 1px solid #eee; text-align: left; font-size: 13px; }
th { font-weight: 600; background: #f8f8f8; position: sticky; top: 0; }
tr:hover { background: #f0f8ff; cursor: pointer; }
.error { color: #e74c3c; padding: 8px; }
.loading { padding: 8px; color: #666; }
.no-results { padding: 8px; color: #999; }
</style>
