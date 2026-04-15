<script setup lang="ts">
import { ref } from 'vue'
import Button from 'primevue/button'
import ProgressBar from 'primevue/progressbar'
import { useToast } from 'primevue/usetoast'

const props = defineProps<{ engagementId: string }>()
const emit = defineEmits<{ (e: 'rebuild-complete'): void }>()
const toast = useToast()

const rebuilding = ref(false)
const pollTimer = ref<ReturnType<typeof setInterval> | null>(null)

async function startRebuild() {
  rebuilding.value = true
  try {
    const resp = await fetch('/api/chain/rebuild', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ engagement_id: props.engagementId || null }),
    })
    if (!resp.ok) throw new Error('Failed to start rebuild')
    const { run_id } = await resp.json()
    pollStatus(run_id)
  } catch {
    rebuilding.value = false
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to start chain analysis', life: 5000 })
  }
}

function pollStatus(runId: string) {
  pollTimer.value = setInterval(async () => {
    try {
      const resp = await fetch(`/api/chain/runs/${runId}`, { credentials: 'include' })
      if (!resp.ok) return
      const run = await resp.json()
      if (run.status === 'done' || run.status === 'completed') {
        clearInterval(pollTimer.value!)
        pollTimer.value = null
        rebuilding.value = false
        emit('rebuild-complete')
      } else if (run.status === 'failed' || run.status === 'error') {
        clearInterval(pollTimer.value!)
        pollTimer.value = null
        rebuilding.value = false
        toast.add({ severity: 'error', summary: 'Analysis Failed', detail: run.error || 'Unknown error', life: 5000 })
      }
    } catch {
      // Silently retry on network error
    }
  }, 2000)
}
</script>

<template>
  <div class="flex flex-col items-center justify-center h-full gap-4">
    <i class="pi pi-share-alt text-6xl text-surface-300" />
    <h2 class="text-xl font-semibold text-surface-500">No attack chain data yet</h2>
    <p class="text-surface-400">Run chain analysis to extract relationships between findings.</p>
    <Button
      v-if="!rebuilding"
      label="Run Chain Analysis"
      icon="pi pi-play"
      @click="startRebuild"
    />
    <div v-else class="w-64">
      <ProgressBar mode="indeterminate" />
      <p class="text-sm text-surface-400 text-center mt-2">Analyzing findings...</p>
    </div>
  </div>
</template>
