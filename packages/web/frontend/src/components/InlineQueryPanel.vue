<!-- packages/web/frontend/src/components/InlineQueryPanel.vue -->
<template>
  <div class="inline-query-panel" :class="{ collapsed: !expanded }">
    <button class="toggle-btn" @click="expanded = !expanded">
      {{ expanded ? 'Hide Query' : 'Query' }}
    </button>
    <div v-if="expanded" class="panel-content">
      <CypherEditor v-model="queryText" :disabled="loading" @run="runQuery" />
      <div class="panel-actions">
        <button class="run-btn" @click="runQuery" :disabled="loading">
          {{ loading ? 'Running...' : 'Run (Ctrl+Enter)' }}
        </button>
      </div>
      <div v-if="error" class="error">{{ error }}</div>
      <div v-if="result" class="inline-results">
        <div class="stats">
          {{ result.stats.rows_returned }} rows, {{ result.stats.duration_ms.toFixed(1) }}ms
        </div>
        <table v-if="result.rows.length > 0">
          <thead>
            <tr>
              <th v-for="col in result.columns" :key="col">{{ col }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(row, idx) in result.rows.slice(0, 20)" :key="idx">
              <td v-for="col in result.columns" :key="col">{{ formatCell(row[col]) }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="result.rows.length > 20" class="more-rows">
          ... {{ result.rows.length - 20 }} more rows
        </div>
        <div v-if="result.rows.length === 0" class="no-results">No results</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import CypherEditor from '@/components/CypherEditor.vue'

const props = defineProps<{
  engagementId?: string | null
}>()

const emit = defineEmits<{
  highlight: [nodeIds: string[]]
}>()

const expanded = ref(false)
const queryText = ref('MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b')
const result = ref<any>(null)
const loading = ref(false)
const error = ref<string | null>(null)

function formatCell(value: any): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

async function runQuery() {
  loading.value = true
  error.value = null
  result.value = null

  try {
    const body: any = { query: queryText.value }
    if (props.engagementId) {
      body.engagement_id = props.engagementId
    }

    const response = await fetch('/api/chain/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      const data = await response.json().catch(() => ({ detail: response.statusText }))
      error.value = data.detail || `Error ${response.status}`
      return
    }

    result.value = await response.json()

    if (result.value?.subgraph?.nodes) {
      const nodeIds = result.value.subgraph.nodes.map((n: any) => n.id).filter(Boolean)
      emit('highlight', nodeIds)
    }
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.inline-query-panel {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  background: var(--p-surface-900, #1a1a2e);
  border-top: 2px solid var(--p-surface-700, #333);
  z-index: 10;
  max-height: 50%;
  overflow: auto;
}
.inline-query-panel.collapsed { max-height: 32px; overflow: hidden; }
.toggle-btn {
  width: 100%;
  padding: 6px;
  text-align: center;
  cursor: pointer;
  background: var(--p-surface-800, #16213e);
  color: var(--p-surface-200);
  border: none;
  font-size: 13px;
}
.toggle-btn:hover { background: var(--p-surface-700); }
.panel-content { padding: 8px; }
.panel-actions {
  display: flex;
  justify-content: flex-end;
  margin: 4px 0;
}
.run-btn {
  padding: 3px 10px;
  background: #2196F3;
  color: white;
  border: none;
  border-radius: 3px;
  cursor: pointer;
  font-size: 12px;
}
.run-btn:disabled { opacity: 0.5; }
.error { color: var(--p-red-400); padding: 4px 0; font-size: 13px; }
.stats { font-size: 12px; color: var(--p-surface-400); padding: 2px 0; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 3px 6px; border-bottom: 1px solid var(--p-surface-700, #333); text-align: left; }
th { background: var(--p-surface-800); color: var(--p-surface-200); font-weight: 600; }
.more-rows { font-size: 12px; color: var(--p-surface-500); padding: 4px; }
.no-results { font-size: 12px; color: var(--p-surface-500); padding: 4px; }
.inline-results { max-height: 200px; overflow: auto; }
</style>
