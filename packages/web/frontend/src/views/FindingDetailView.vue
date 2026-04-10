<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'
import SeverityBadge from '@/components/SeverityBadge.vue'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const queryClient = useQueryClient()

const findingId = route.params.id as string

const { data: finding, isLoading } = useQuery({
  queryKey: ['finding', findingId],
  queryFn: () =>
    fetch(`/api/v1/findings/${findingId}`, { credentials: 'include' }).then(r => r.json()),
})

// Status cycle: open → confirmed → remediated → false_positive → open
const statusCycle: Record<string, string> = {
  open: 'confirmed',
  confirmed: 'remediated',
  remediated: 'false_positive',
  false_positive: 'open',
}

const statusMutation = useMutation({
  mutationFn: (newStatus: string) =>
    fetch(`/api/v1/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
      credentials: 'include',
    }).then(r => {
      if (!r.ok) throw new Error('Failed')
      return r.json()
    }),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['finding', findingId] })
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    toast.add({ severity: 'success', summary: 'Updated', detail: 'Status updated', life: 3000 })
  },
  onError: () =>
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to update status', life: 3000 }),
})

const fpMutation = useMutation({
  mutationFn: () =>
    fetch(`/api/v1/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'false_positive' }),
      credentials: 'include',
    }).then(r => {
      if (!r.ok) throw new Error('Failed')
      return r.json()
    }),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['finding', findingId] })
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    toast.add({ severity: 'info', summary: 'Flagged', detail: 'Marked as false positive', life: 3000 })
  },
  onError: () =>
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to flag finding', life: 3000 }),
})

function cycleStatus() {
  const current = finding.value?.status ?? 'open'
  const next = statusCycle[current] ?? 'open'
  statusMutation.mutate(next)
}

function formatDate(d: string) {
  if (!d) return '—'
  return new Date(d).toLocaleString()
}
</script>

<template>
  <div>
    <!-- Back button -->
    <Button
      icon="pi pi-arrow-left"
      label="Back"
      text
      class="mb-4"
      @click="router.back()"
    />

    <div v-if="isLoading" class="flex justify-center mt-8">
      <ProgressSpinner />
    </div>

    <div v-else-if="finding" class="max-w-4xl">
      <!-- Title + badges -->
      <div class="flex flex-wrap items-start gap-3 mb-6">
        <h1 class="text-2xl font-bold flex-1">{{ finding.title }}</h1>
        <div class="flex gap-2 flex-wrap">
          <SeverityBadge :severity="finding.severity" />
          <Tag
            :value="finding.status?.replace('_', ' ').toUpperCase()"
            :severity="
              finding.status === 'confirmed'
                ? 'danger'
                : finding.status === 'remediated'
                ? 'success'
                : finding.status === 'false_positive'
                ? 'secondary'
                : 'warn'
            "
          />
        </div>
      </div>

      <!-- Metadata grid -->
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6 p-4 border border-surface-200 rounded">
        <div>
          <p class="text-xs text-surface-500 uppercase tracking-wide mb-1">CWE</p>
          <p class="font-medium">{{ finding.cwe ?? '—' }}</p>
        </div>
        <div>
          <p class="text-xs text-surface-500 uppercase tracking-wide mb-1">Tool</p>
          <p class="font-medium">{{ finding.tool ?? '—' }}</p>
        </div>
        <div>
          <p class="text-xs text-surface-500 uppercase tracking-wide mb-1">Phase</p>
          <p class="font-medium">{{ finding.phase ?? '—' }}</p>
        </div>
        <div>
          <p class="text-xs text-surface-500 uppercase tracking-wide mb-1">Corroboration</p>
          <p class="font-medium">{{ finding.corroboration_count ?? 0 }}</p>
        </div>
        <div class="col-span-2">
          <p class="text-xs text-surface-500 uppercase tracking-wide mb-1">Location</p>
          <p class="font-mono text-sm break-all">{{ finding.location ?? '—' }}</p>
        </div>
        <div>
          <p class="text-xs text-surface-500 uppercase tracking-wide mb-1">Discovered</p>
          <p class="text-sm">{{ formatDate(finding.created_at) }}</p>
        </div>
        <div>
          <p class="text-xs text-surface-500 uppercase tracking-wide mb-1">Updated</p>
          <p class="text-sm">{{ formatDate(finding.updated_at) }}</p>
        </div>
      </div>

      <!-- Description -->
      <section class="mb-6">
        <h2 class="text-lg font-semibold mb-2">Description</h2>
        <p class="text-surface-700 whitespace-pre-wrap">{{ finding.description ?? 'No description provided.' }}</p>
      </section>

      <!-- Evidence -->
      <section v-if="finding.evidence" class="mb-6">
        <h2 class="text-lg font-semibold mb-2">Evidence</h2>
        <pre class="bg-surface-100 dark:bg-surface-800 rounded p-4 overflow-x-auto text-sm font-mono whitespace-pre-wrap">{{ finding.evidence }}</pre>
      </section>

      <!-- Remediation -->
      <section v-if="finding.remediation" class="mb-6">
        <h2 class="text-lg font-semibold mb-2">Remediation</h2>
        <p class="text-surface-700 whitespace-pre-wrap">{{ finding.remediation }}</p>
      </section>

      <!-- Actions -->
      <div class="flex gap-2 flex-wrap">
        <Button
          label="Cycle Status"
          icon="pi pi-refresh"
          :loading="statusMutation.isPending.value"
          @click="cycleStatus"
        />
        <Button
          v-if="finding.status !== 'false_positive'"
          label="Flag False Positive"
          icon="pi pi-flag"
          severity="secondary"
          :loading="fpMutation.isPending.value"
          @click="fpMutation.mutate()"
        />
      </div>
    </div>

    <p v-else class="text-center text-surface-500 mt-8">Finding not found.</p>
  </div>
</template>
