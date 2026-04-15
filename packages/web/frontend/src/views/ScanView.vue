<template>
  <div class="scan-page">
    <h1 class="text-2xl font-bold mb-4">Scans</h1>

    <!-- New Scan Form -->
    <div class="new-scan-form card mb-6 p-4 border rounded">
      <h2 class="text-lg font-semibold mb-3">New Scan</h2>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label class="block text-sm font-medium mb-1">Target Type</label>
          <select v-model="targetType" class="w-full border rounded p-2">
            <option value="url">URL / Domain</option>
            <option value="network">IP / CIDR Range</option>
            <option value="file">File Path (binary, APK, source)</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">Engagement</label>
          <select v-model="engagementId" class="w-full border rounded p-2">
            <option v-for="eng in engagements" :key="eng.id" :value="eng.id">{{ eng.name }}</option>
          </select>
        </div>
      </div>

      <div class="mb-4">
        <label class="block text-sm font-medium mb-1">Target</label>
        <div v-if="targetType === 'file'" class="flex gap-2">
          <input v-model="target" type="text" class="flex-1 border rounded p-2" placeholder="/workspace/sample.exe or upload a file" />
          <label class="cursor-pointer bg-gray-100 border rounded p-2 hover:bg-gray-200">
            Upload
            <input type="file" class="hidden" @change="onFileUpload" />
          </label>
        </div>
        <input v-else v-model="target" type="text" class="w-full border rounded p-2"
          :placeholder="targetType === 'url' ? 'https://example.com' : '10.0.0.0/24'" />
      </div>

      <div class="flex gap-4 mb-4">
        <div>
          <label class="block text-sm font-medium mb-1">Mode</label>
          <select v-model="mode" class="border rounded p-2">
            <option value="auto">Auto</option>
            <option value="assisted">Assisted</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">Concurrency</label>
          <input v-model.number="concurrency" type="number" min="1" max="32" class="border rounded p-2 w-20" />
        </div>
      </div>

      <button @click="startScan" :disabled="!target || !engagementId || scanning"
        class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 disabled:opacity-50">
        {{ scanning ? 'Starting...' : 'Start Scan' }}
      </button>
      <span v-if="scanError" class="ml-4 text-red-500">{{ scanError }}</span>
      <span v-if="uploadStatus" class="ml-4 text-gray-500">{{ uploadStatus }}</span>
    </div>

    <!-- Scan List -->
    <div v-if="scansLoading" class="text-center py-8 text-gray-500">Loading scans...</div>
    <div v-else-if="scans.length === 0" class="text-center py-8 text-gray-500">No scans yet. Start one above.</div>
    <div v-else class="space-y-3">
      <div v-for="scan in scans" :key="scan.id"
        class="border rounded p-4 cursor-pointer hover:bg-gray-50"
        :class="{ 'border-blue-400 bg-blue-50': activeScanId === scan.id }"
        @click="activeScanId = activeScanId === scan.id ? null : scan.id">
        <div class="flex justify-between items-center">
          <div>
            <span class="font-medium">{{ scan.target }}</span>
            <span class="ml-2 text-sm text-gray-500">({{ scan.target_type }})</span>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-sm">{{ scan.finding_count }} findings</span>
            <span class="px-2 py-0.5 rounded text-xs font-medium"
              :class="{
                'bg-yellow-100 text-yellow-800': scan.status === 'pending' || scan.status === 'running',
                'bg-green-100 text-green-800': scan.status === 'completed',
                'bg-red-100 text-red-800': scan.status === 'failed',
                'bg-gray-100 text-gray-800': scan.status === 'cancelled' || scan.status === 'paused',
              }">
              {{ scan.status }}
            </span>
          </div>
        </div>
        <div class="text-xs text-gray-400 mt-1">
          {{ scan.tools_planned?.join(', ') || 'no tools' }} &middot; {{ scan.created_at }}
        </div>

        <!-- Expanded detail -->
        <div v-if="activeScanId === scan.id" class="mt-4 border-t pt-3">
          <div v-if="scanTasks[scan.id]" class="space-y-1">
            <div v-for="task in scanTasks[scan.id]" :key="task.id"
              class="flex items-center gap-2 text-sm">
              <span class="w-2 h-2 rounded-full"
                :class="{
                  'bg-gray-300': task.status === 'pending',
                  'bg-blue-500 animate-pulse': task.status === 'running',
                  'bg-green-500': task.status === 'completed',
                  'bg-red-500': task.status === 'failed',
                }"></span>
              <span>{{ task.name }}</span>
              <span class="text-gray-400">({{ task.tool }})</span>
              <span v-if="task.duration_ms" class="text-gray-400">{{ task.duration_ms }}ms</span>
            </div>
          </div>
          <div v-else class="text-sm text-gray-400">Loading tasks...</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'

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

onMounted(async () => {
  // Load engagements
  try {
    const res = await fetch('/api/v1/engagements', { credentials: 'include' })
    if (res.ok) {
      const data = await res.json()
      engagements.value = data.items || []
      if (engagements.value.length > 0) {
        engagementId.value = engagements.value[0].id
      }
    }
  } catch (e) {}

  // Load scans
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

async function onFileUpload(event: Event) {
  const input = event.target as HTMLInputElement
  if (!input.files?.length) return

  const file = input.files[0]
  uploadStatus.value = `Uploading ${file.name}...`

  const formData = new FormData()
  formData.append('file', file)

  try {
    const res = await fetch('/api/v1/scans/upload', {
      method: 'POST',
      credentials: 'include',
      body: formData,
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
      method: 'POST',
      credentials: 'include',
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
  } catch (e: any) {
    scanError.value = e.message
  } finally {
    scanning.value = false
  }
}
</script>

<style scoped>
.scan-page { padding: 16px; max-width: 1000px; margin: 0 auto; }
</style>
