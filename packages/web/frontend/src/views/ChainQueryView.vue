<!-- packages/web/frontend/src/views/ChainQueryView.vue -->
<template>
  <div class="chain-query-page">
    <h1>Chain Query</h1>
    <div class="editor-section">
      <CypherEditor v-model="queryText" :disabled="loading" @run="runQuery" />
    </div>
    <div class="results-section">
      <QueryResultsPane
        :result="result"
        :loading="loading"
        :error="error"
        @row-click="onRowClick"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import CypherEditor from '@/components/CypherEditor.vue'
import QueryResultsPane from '@/components/QueryResultsPane.vue'

const queryText = ref('MATCH (a:Finding) RETURN a')
const result = ref<any>(null)
const loading = ref(false)
const error = ref<string | null>(null)

async function runQuery() {
  loading.value = true
  error.value = null
  result.value = null

  try {
    const response = await fetch('/api/chain/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: queryText.value }),
    })

    if (!response.ok) {
      const data = await response.json().catch(() => ({ detail: response.statusText }))
      error.value = data.detail || `Error ${response.status}`
      return
    }

    result.value = await response.json()
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function onRowClick(row: any, index: number) {
  // Future: highlight in graph preview
}
</script>

<style scoped>
.chain-query-page { padding: 16px; max-width: 1200px; margin: 0 auto; }
.editor-section { margin-bottom: 12px; }
.results-section { border: 1px solid #eee; border-radius: 4px; min-height: 200px; }
</style>
