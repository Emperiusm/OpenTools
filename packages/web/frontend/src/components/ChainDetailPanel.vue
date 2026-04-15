<script setup lang="ts">
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import SeverityBadge from '@/components/SeverityBadge.vue'

interface GraphNode {
  id: string
  name: string
  severity: string
  tool: string
  phase: string | null
  neighborCount?: number
  pivotality?: number
}

interface GraphLink {
  id: string
  source: string | { id: string }
  target: string | { id: string }
  value: number
  status: string
  drift: boolean
  reasons: string[]
  relation_type: string | null
  rationale: string | null
  weight_model_version?: string
}

const props = defineProps<{
  selectedNode: GraphNode | null
  selectedLink: GraphLink | null
  nodes: GraphNode[]
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'confirm', linkId: string): void
  (e: 'reject', linkId: string): void
  (e: 'expand', nodeId: string): void
  (e: 'export-path'): void
}>()

function findNode(ref: string | { id: string }): GraphNode | undefined {
  const id = typeof ref === 'string' ? ref : ref.id
  return props.nodes.find(n => n.id === id)
}

const statusMap: Record<string, { label: string; severity: 'success' | 'warn' | 'danger' | 'info' | 'secondary' }> = {
  auto_confirmed: { label: 'Auto Confirmed', severity: 'success' },
  user_confirmed: { label: 'Confirmed', severity: 'success' },
  candidate: { label: 'Candidate', severity: 'warn' },
  rejected: { label: 'Rejected', severity: 'danger' },
  user_rejected: { label: 'Rejected', severity: 'danger' },
}

function getStatusDisplay(status: string) {
  return statusMap[status] ?? { label: status, severity: 'secondary' as const }
}
</script>

<template>
  <div
    v-if="selectedNode || selectedLink"
    class="w-80 border-l border-surface-200 dark:border-surface-700 overflow-y-auto p-4 flex flex-col gap-4"
  >
    <!-- Header -->
    <div class="flex items-center justify-between">
      <span class="font-semibold text-surface-700 dark:text-surface-200">
        {{ selectedNode ? 'Node Details' : 'Edge Details' }}
      </span>
      <Button icon="pi pi-times" text rounded size="small" @click="emit('close')" aria-label="Close panel" />
    </div>

    <!-- Node details -->
    <template v-if="selectedNode">
      <div class="flex flex-col gap-2">
        <div class="text-base font-medium text-surface-800 dark:text-surface-100 break-words">
          {{ selectedNode.name }}
        </div>
        <div class="flex items-center gap-2 flex-wrap">
          <SeverityBadge :severity="selectedNode.severity" />
        </div>
        <div class="text-sm text-surface-500 dark:text-surface-400">
          <span class="font-medium">Tool:</span> {{ selectedNode.tool }}
        </div>
        <div v-if="selectedNode.phase" class="text-sm text-surface-500 dark:text-surface-400">
          <span class="font-medium">Phase:</span> {{ selectedNode.phase }}
        </div>
        <div v-if="selectedNode.neighborCount !== undefined" class="text-sm text-surface-500 dark:text-surface-400">
          <span class="font-medium">Neighbors:</span> {{ selectedNode.neighborCount }}
        </div>
        <div v-if="selectedNode.pivotality && selectedNode.pivotality > 0.1" class="text-sm text-surface-500 dark:text-surface-400">
          <span class="font-medium">Pivotality:</span> {{ (selectedNode.pivotality * 100).toFixed(0) }}%
        </div>
      </div>
      <Button
        label="Expand Neighbors"
        icon="pi pi-share-alt"
        size="small"
        outlined
        @click="emit('expand', selectedNode.id)"
      />
    </template>

    <!-- Link details -->
    <template v-if="selectedLink">
      <!-- Source → Target -->
      <div class="flex flex-col gap-1">
        <div class="text-xs uppercase text-surface-400 font-semibold tracking-wide">Source</div>
        <div class="text-sm text-surface-800 dark:text-surface-100 break-words font-medium">
          {{ findNode(selectedLink.source)?.name ?? (typeof selectedLink.source === 'string' ? selectedLink.source : selectedLink.source.id) }}
        </div>
        <div class="flex justify-center text-surface-400">
          <i class="pi pi-arrow-down text-xs" />
        </div>
        <div class="text-xs uppercase text-surface-400 font-semibold tracking-wide">Target</div>
        <div class="text-sm text-surface-800 dark:text-surface-100 break-words font-medium">
          {{ findNode(selectedLink.target)?.name ?? (typeof selectedLink.target === 'string' ? selectedLink.target : selectedLink.target.id) }}
        </div>
      </div>

      <!-- Weight + Status -->
      <div class="flex items-center gap-2 flex-wrap">
        <span class="text-sm text-surface-500 dark:text-surface-400">
          <span class="font-medium">Weight:</span> {{ selectedLink.value.toFixed(2) }}
        </span>
        <Tag
          :value="getStatusDisplay(selectedLink.status).label"
          :severity="getStatusDisplay(selectedLink.status).severity"
        />
        <Tag
          v-if="selectedLink.weight_model_version === 'bayesian_v1'"
          value="Calibrated"
          severity="info"
        />
        <Tag
          v-if="selectedLink.relation_type"
          :value="selectedLink.relation_type"
          severity="secondary"
        />
      </div>

      <!-- Drift warning -->
      <div
        v-if="selectedLink.drift"
        class="flex items-start gap-2 rounded bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 p-3 text-sm text-yellow-800 dark:text-yellow-300"
      >
        <i class="pi pi-exclamation-triangle mt-0.5 shrink-0" />
        <span>Reasoning changed since you confirmed this edge.</span>
      </div>

      <!-- Rule reasons -->
      <div v-if="selectedLink.reasons && selectedLink.reasons.length > 0" class="flex flex-col gap-1">
        <div class="text-xs uppercase text-surface-400 font-semibold tracking-wide">Rule Reasons</div>
        <ul class="list-disc list-inside text-sm text-surface-600 dark:text-surface-300 space-y-0.5">
          <li v-for="(reason, idx) in selectedLink.reasons" :key="idx">{{ reason }}</li>
        </ul>
      </div>

      <!-- LLM Rationale -->
      <div v-if="selectedLink.rationale" class="flex flex-col gap-1">
        <div class="text-xs uppercase text-surface-400 font-semibold tracking-wide">LLM Rationale</div>
        <p class="text-sm text-surface-600 dark:text-surface-300 whitespace-pre-wrap break-words">
          {{ selectedLink.rationale }}
        </p>
      </div>

      <!-- Curation buttons -->
      <div class="flex gap-2 pt-1">
        <Button
          label="Confirm"
          icon="pi pi-check"
          severity="success"
          size="small"
          :disabled="selectedLink.status === 'user_confirmed'"
          @click="emit('confirm', selectedLink.id)"
          class="flex-1"
        />
        <Button
          label="Reject"
          icon="pi pi-times"
          severity="danger"
          size="small"
          :disabled="selectedLink.status === 'user_rejected'"
          @click="emit('reject', selectedLink.id)"
          class="flex-1"
        />
      </div>

      <!-- Export path -->
      <Button
        label="Export Path"
        icon="pi pi-download"
        outlined
        size="small"
        class="mt-2"
        @click="emit('export-path')"
      />
    </template>
  </div>
</template>
