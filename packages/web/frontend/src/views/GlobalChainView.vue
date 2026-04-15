<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useQuery, useMutation } from '@tanstack/vue-query'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'

import ForceGraphCanvas from '@/components/ForceGraphCanvas.vue'
import ChainDetailPanel from '@/components/ChainDetailPanel.vue'
import ChainFilterToolbar from '@/components/ChainFilterToolbar.vue'
import ChainLegend from '@/components/ChainLegend.vue'
import ChainTimelineScrubber from '@/components/ChainTimelineScrubber.vue'
import EngagementFilterChips from '@/components/EngagementFilterChips.vue'
import ChainEmptyState from '@/components/ChainEmptyState.vue'

const router = useRouter()
const toast = useToast()

const filters = ref({ severities: [] as string[], statuses: [] as string[] })
const engagementIds = ref<string[] | null>(null)
const layoutMode = ref<'force' | 'killchain'>('force')
const timeRange = ref<{ start: Date; end: Date } | null>(null)

function onFilterChange(f: { severities: string[]; statuses: string[] }) {
  filters.value = f
}

function onEngagementChange(ids: string[]) {
  engagementIds.value = ids.length > 0 ? ids : null
}

const queryParams = computed(() => {
  const params = new URLSearchParams({ max_nodes: '500' })
  if (engagementIds.value) {
    params.set('engagement_ids', engagementIds.value.join(','))
  }
  if (filters.value.severities.length > 0 && filters.value.severities.length < 5) {
    params.set('severity', filters.value.severities.join(','))
  }
  if (filters.value.statuses.length > 0) {
    params.set('status', filters.value.statuses.join(','))
  }
  return params.toString()
})

const { data: subgraphData, isLoading, refetch } = useQuery({
  queryKey: ['chain-subgraph-global', queryParams],
  queryFn: () =>
    fetch(`/api/chain/subgraph?${queryParams.value}`, { credentials: 'include' })
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch subgraph')
        return r.json()
      }),
})

const graphData = computed(() => subgraphData.value?.graph ?? { nodes: [], links: [] })
const meta = computed(() => subgraphData.value?.meta ?? { total_findings: 0, rendered_findings: 0, filtered: false, generation: 0, engagements: [] })
const isEmpty = computed(() => !isLoading.value && meta.value.total_findings === 0)

const ENGAGEMENT_COLORS = [
  '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6',
  '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
]
const engagementColorMap = computed(() => {
  const map: Record<string, string> = {}
  for (let i = 0; i < meta.value.engagements.length; i++) {
    map[meta.value.engagements[i].id] = ENGAGEMENT_COLORS[i % ENGAGEMENT_COLORS.length]
  }
  return map
})

const selectedNode = ref<any>(null)
const selectedLink = ref<any>(null)

function onNodeClick(node: any) {
  selectedLink.value = null
  selectedNode.value = {
    ...node,
    neighborCount: graphData.value.links.filter((l: any) => {
      const srcId = typeof l.source === 'string' ? l.source : l.source.id
      const tgtId = typeof l.target === 'string' ? l.target : l.target.id
      return srcId === node.id || tgtId === node.id
    }).length,
  }
}

function onLinkClick(link: any) {
  selectedNode.value = null
  selectedLink.value = link
}

function onBackgroundClick() {
  selectedNode.value = null
  selectedLink.value = null
}

const curateMutation = useMutation({
  mutationFn: ({ relationId, status }: { relationId: string; status: string }) =>
    fetch(`/api/chain/relations/${relationId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ status }),
    }).then(r => {
      if (!r.ok) throw new Error('Curation failed')
      return r.json()
    }),
  onSuccess: (data, variables) => {
    const link = graphData.value.links.find((l: any) => l.id === variables.relationId)
    if (link) {
      link.status = variables.status
      if (variables.status === 'user_confirmed') link.drift = false
    }
    if (selectedLink.value?.id === variables.relationId) {
      selectedLink.value = { ...selectedLink.value, status: variables.status }
    }
    toast.add({ severity: 'success', summary: 'Updated', detail: `Edge ${variables.status === 'user_confirmed' ? 'confirmed' : 'rejected'}`, life: 2000 })
  },
  onError: () => toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to update edge', life: 3000 }),
})

function onConfirm(linkId: string) { curateMutation.mutate({ relationId: linkId, status: 'user_confirmed' }) }
function onReject(linkId: string) { curateMutation.mutate({ relationId: linkId, status: 'user_rejected' }) }

async function onExportPath() {
  toast.add({ severity: 'info', summary: 'Export', detail: 'Select a path via the per-engagement view to export', life: 3000 })
}

async function runCalibration() {
  try {
    const resp = await fetch('/api/chain/calibrate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ scope: 'user' }),
    })
    if (!resp.ok) {
      const err = await resp.json()
      toast.add({ severity: 'warn', summary: 'Calibration', detail: err.detail || 'Failed', life: 5000 })
      return
    }
    const data = await resp.json()
    toast.add({ severity: 'success', summary: 'Calibrated', detail: `${data.edges_updated} edges updated`, life: 3000 })
    refetch()
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Calibration failed', life: 3000 })
  }
}

function toggleLayout() {
  layoutMode.value = layoutMode.value === 'force' ? 'killchain' : 'force'
}
</script>

<template>
  <div class="flex flex-col h-screen">
    <div class="flex items-center gap-3 p-3 border-b border-surface-200 dark:border-surface-700 flex-wrap">
      <h1 class="text-lg font-bold">Attack Chain — Global</h1>
      <ChainFilterToolbar @filter-change="onFilterChange" />
      <Button
        :label="layoutMode === 'force' ? 'Kill Chain' : 'Force'"
        icon="pi pi-th-large"
        text size="small"
        @click="toggleLayout"
      />
      <Button
        label="Calibrate"
        icon="pi pi-sliders-h"
        text size="small"
        @click="runCalibration"
      />
    </div>

    <div v-if="meta.engagements.length > 1" class="px-4 py-2 border-b border-surface-200 dark:border-surface-700">
      <EngagementFilterChips
        :engagements="meta.engagements"
        @change="onEngagementChange"
      />
    </div>

    <div v-if="isLoading" class="flex-1 flex items-center justify-center">
      <ProgressSpinner />
    </div>

    <div v-else-if="isEmpty" class="flex-1 flex items-center justify-center">
      <ChainEmptyState
        :engagement-id="engagementIds?.length === 1 ? engagementIds[0] : ''"
        @rebuild-complete="refetch()"
      />
    </div>

    <template v-else>
      <div class="flex flex-1 overflow-hidden">
        <ForceGraphCanvas
          :data="graphData"
          :selected-node-id="selectedNode?.id ?? null"
          :selected-link-id="selectedLink?.id ?? null"
          :time-range="timeRange"
          :layout-mode="layoutMode"
          color-mode="engagement"
          :engagement-colors="engagementColorMap"
          class="flex-1"
          @node-click="onNodeClick"
          @link-click="onLinkClick"
          @background-click="onBackgroundClick"
        />
        <ChainDetailPanel
          :selected-node="selectedNode"
          :selected-link="selectedLink"
          :nodes="graphData.nodes"
          @close="onBackgroundClick"
          @confirm="onConfirm"
          @reject="onReject"
          @expand="() => {}"
          @export-path="onExportPath"
        />
      </div>
    </template>

    <ChainTimelineScrubber
      :nodes="graphData.nodes"
      @time-range-change="(r: any) => timeRange = r"
    />

    <ChainLegend
      :rendered-count="meta.rendered_findings"
      :total-count="meta.total_findings"
    />
  </div>
</template>
