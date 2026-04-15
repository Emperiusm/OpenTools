<script setup lang="ts">
import { ref, onMounted, watch, computed } from 'vue'
import Card from 'primevue/card'
import Button from 'primevue/button'
import Select from 'primevue/select'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Tag from 'primevue/tag'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import FileUpload from 'primevue/fileupload'
import ProgressSpinner from 'primevue/progressspinner'
import Message from 'primevue/message'
import Divider from 'primevue/divider'

const target = ref('')
const targetType = ref('url')
const engagementId = ref('')
const mode = ref('auto')
const concurrency = ref(8)
const scanning = ref(false)
const scanError = ref('')
const uploadStatus = ref('')

const engagements = ref<any[]>([])
const scans = ref<any[]>([])
const scansLoading = ref(true)
const activeScanId = ref<string | null>(null)
const scanTasks = ref<Record<string, any[]>>({})

const targetTypeOptions = [
  { label: 'URL / Domain', value: 'url' },
  { label: 'IP / CIDR Range', value: 'network' },
  { label: 'File Path (binary, APK, source)', value: 'file' },
]

const modeOptions = [
  { label: 'Auto', value: 'auto' },
  { label: 'Assisted', value: 'assisted' },
]

const targetPlaceholder = computed(() => {
  if (targetType.value === 'url') return 'https://example.com'
  if (targetType.value === 'network') return '10.0.0.0/24'
  return '/workspace/sample.exe'
})

function statusSeverity(status: string): string {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'running') return 'info'
  if (status === 'cancelled' || status === 'paused') return 'secondary'
  return 'warn'
}

function taskStatusIcon(status: string): string {
  if (status === 'completed') return 'pi pi-check-circle'
  if (status === 'failed') return 'pi pi-times-circle'
  if (status === 'running') return 'pi pi-spin pi-spinner'
  return 'pi pi-circle'
}

function taskStatusColor(status: string): string {
  if (status === 'completed') return 'color: var(--p-green-500)'
  if (status === 'failed') return 'color: var(--p-red-500)'
  if (status === 'running') return 'color: var(--p-blue-500)'
  return 'color: var(--p-surface-400)'
}

function formatDate(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

onMounted(async () => {
  try {
    const res = await fetch('/api/v1/engagements', { credentials: 'include' })
    if (res.ok) {
      const data = await res.json()
      engagements.value = (data.items || []).map((e: any) => ({ label: e.name, value: e.id }))
      if (engagements.value.length > 0) {
        engagementId.value = engagements.value[0].value
      }
    }
  } catch (e) {}
  await loadScans()
})

async function loadScans() {
  scansLoading.value = true
  try {
    const res = await fetch('/api/v1/scans', { credentials: 'include' })
    if (res.ok) {
      const data = await res.json()
      scans.value = data.items || []
    }
  } catch (e) {}
  scansLoading.value = false
}

watch(activeScanId, async (id) => {
  if (id && !scanTasks.value[id]) {
    try {
      const res = await fetch(`/api/v1/scans/${id}/tasks`, { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        scanTasks.value[id] = data.tasks || []
      }
    } catch (e) {}
  }
})

async function onFileSelect(event: any) {
  const file = event.files?.[0]
  if (!file) return
  uploadStatus.value = `Uploading ${file.name}...`
  const formData = new FormData()
  formData.append('file', file)
  try {
    const res = await fetch('/api/v1/scans/upload', {
      method: 'POST', credentials: 'include', body: formData,
    })
    if (res.ok) {
      const data = await res.json()
      target.value = data.path
      uploadStatus.value = `Uploaded: ${data.filename} (${(data.size / 1024).toFixed(1)} KB)`
    } else {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }))
      uploadStatus.value = `Error: ${err.detail}`
    }
  } catch (e: any) {
    uploadStatus.value = `Error: ${e.message}`
  }
}

async function startScan() {
  scanning.value = true
  scanError.value = ''
  try {
    const res = await fetch('/api/v1/scans', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target.value,
        engagement_id: engagementId.value,
        mode: mode.value,
        concurrency: concurrency.value,
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Scan creation failed' }))
      scanError.value = err.detail
      return
    }
    const scan = await res.json()
    target.value = ''
    uploadStatus.value = ''
    await loadScans()
    activeScanId.value = scan.id
    // Start polling for status updates
    startPolling(scan.id)
  } catch (e: any) {
    scanError.value = e.message
  } finally {
    scanning.value = false
  }
}

let pollTimer: ReturnType<typeof setInterval> | null = null

function startPolling(scanId: string) {
  stopPolling()
  pollTimer = setInterval(async () => {
    await loadScans()
    // Also refresh tasks for the active scan
    if (activeScanId.value) {
      try {
        const res = await fetch(`/api/v1/scans/${activeScanId.value}/tasks`, { credentials: 'include' })
        if (res.ok) {
          const data = await res.json()
          scanTasks.value[activeScanId.value] = data.tasks || []
        }
      } catch (e) {}
    }
    // Stop polling if scan is done
    const activeScan = scans.value.find(s => s.id === scanId)
    if (activeScan && ['completed', 'failed', 'cancelled'].includes(activeScan.status)) {
      stopPolling()
    }
  }, 3000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

function toggleScan(scanId: string) {
  activeScanId.value = activeScanId.value === scanId ? null : scanId
}
</script>

<template>
  <div class="scan-page">
    <h1 class="text-2xl font-bold mb-4">Scans</h1>

    <!-- New Scan Form -->
    <Card class="mb-5">
      <template #title>New Scan</template>
      <template #content>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div class="flex flex-col gap-1">
            <label class="text-sm font-medium">Target Type</label>
            <Select v-model="targetType" :options="targetTypeOptions" optionLabel="label" optionValue="value" class="w-full" />
          </div>
          <div class="flex flex-col gap-1">
            <label class="text-sm font-medium">Engagement</label>
            <Select v-model="engagementId" :options="engagements" optionLabel="label" optionValue="value" class="w-full" />
          </div>
          <div class="flex flex-col gap-1">
            <label class="text-sm font-medium">Mode</label>
            <Select v-model="mode" :options="modeOptions" optionLabel="label" optionValue="value" class="w-full" />
          </div>
        </div>

        <div class="flex gap-3 items-end mb-4">
          <div class="flex-1 flex flex-col gap-1">
            <label class="text-sm font-medium">Target</label>
            <InputText v-model="target" :placeholder="targetPlaceholder" class="w-full" />
          </div>
          <div v-if="targetType === 'file'" class="flex flex-col gap-1">
            <label class="text-sm font-medium">&nbsp;</label>
            <label class="cursor-pointer">
              <Button label="Upload" icon="pi pi-upload" severity="secondary" size="small" />
              <input type="file" class="hidden" @change="(e: any) => onFileSelect({ files: e.target?.files ? [e.target.files[0]] : [] })" />
            </label>
          </div>
          <div class="flex flex-col gap-1">
            <label class="text-sm font-medium">Workers</label>
            <InputNumber v-model="concurrency" :min="1" :max="32" class="w-20" inputClass="w-20" />
          </div>
        </div>

        <div class="flex items-center gap-3">
          <Button
            :label="scanning ? 'Starting containers & scan...' : 'Start Scan'"
            icon="pi pi-play"
            :loading="scanning"
            :disabled="!target || !engagementId"
            @click="startScan"
          />
          <Message v-if="scanError" severity="error" :closable="false" class="m-0">{{ scanError }}</Message>
          <span v-if="uploadStatus" class="text-sm text-surface-500">{{ uploadStatus }}</span>
        </div>
      </template>
    </Card>

    <!-- Scan History -->
    <Card>
      <template #title>Scan History</template>
      <template #content>
        <div v-if="scansLoading" class="flex justify-center py-6">
          <ProgressSpinner style="width: 40px; height: 40px" />
        </div>

        <p v-else-if="scans.length === 0" class="text-center text-surface-500 py-6">
          No scans yet. Create one above to get started.
        </p>

        <DataTable v-else :value="scans" stripedRows :rowHover="true" selectionMode="single"
          @row-select="(e: any) => toggleScan(e.data.id)" class="scan-table">
          <Column header="Target" style="min-width: 250px">
            <template #body="{ data }">
              <div class="flex flex-col">
                <span class="font-medium">{{ data.target }}</span>
                <span class="text-xs text-surface-400">{{ data.target_type }}</span>
              </div>
            </template>
          </Column>
          <Column header="Status" style="width: 120px">
            <template #body="{ data }">
              <Tag :value="data.status" :severity="statusSeverity(data.status)" />
            </template>
          </Column>
          <Column header="Tools" style="min-width: 200px">
            <template #body="{ data }">
              <div class="flex flex-wrap gap-1">
                <Tag v-for="tool in (data.tools_planned || [])" :key="tool" :value="tool" severity="secondary" class="text-xs" />
              </div>
            </template>
          </Column>
          <Column header="Findings" style="width: 90px; text-align: center">
            <template #body="{ data }">
              <span class="font-semibold" :class="data.finding_count > 0 ? 'text-red-500' : ''">
                {{ data.finding_count }}
              </span>
            </template>
          </Column>
          <Column header="Date" style="width: 150px">
            <template #body="{ data }">
              <span class="text-sm">{{ formatDate(data.created_at) }}</span>
            </template>
          </Column>
          <Column header="" style="width: 50px">
            <template #body="{ data }">
              <Button
                :icon="activeScanId === data.id ? 'pi pi-chevron-up' : 'pi pi-chevron-down'"
                text rounded size="small"
                @click.stop="toggleScan(data.id)"
              />
            </template>
          </Column>
        </DataTable>

        <!-- Expanded Task Detail -->
        <div v-if="activeScanId" class="mt-3 p-3 border-1 surface-border rounded">
          <h3 class="text-sm font-semibold mb-2 text-surface-600">
            Tasks for {{ scans.find(s => s.id === activeScanId)?.target }}
          </h3>
          <div v-if="!scanTasks[activeScanId]" class="flex justify-center py-3">
            <ProgressSpinner style="width: 24px; height: 24px" />
          </div>
          <div v-else class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            <div v-for="task in scanTasks[activeScanId]" :key="task.id"
              class="flex items-center gap-2 p-2 rounded surface-ground">
              <i :class="taskStatusIcon(task.status)" :style="taskStatusColor(task.status)"></i>
              <div class="flex-1 min-w-0">
                <div class="font-medium text-sm truncate">{{ task.name }}</div>
                <div class="text-xs text-surface-400">{{ task.tool }}</div>
              </div>
              <span v-if="task.duration_ms" class="text-xs text-surface-400 whitespace-nowrap">
                {{ (task.duration_ms / 1000).toFixed(1) }}s
              </span>
            </div>
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>

<style scoped>
.scan-page {
  padding: 16px;
  max-width: 1100px;
  margin: 0 auto;
}
</style>
