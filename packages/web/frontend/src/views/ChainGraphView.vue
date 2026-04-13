<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'

import ForceGraphCanvas from '@/components/ForceGraphCanvas.vue'
import ChainDetailPanel from '@/components/ChainDetailPanel.vue'
import ChainFilterToolbar from '@/components/ChainFilterToolbar.vue'
import ChainLegend from '@/components/ChainLegend.vue'
import ChainEmptyState from '@/components/ChainEmptyState.vue'
import ChainTimelineScrubber from '@/components/ChainTimelineScrubber.vue'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const queryClient = useQueryClient()

const engId = route.params.id as string

// Filter state
const filters = ref({ severities: [] as string[], statuses: [] as string[] })

const layoutMode = ref<'force' | 'killchain'>('force')
const timeRange = ref<{ start: Date; end: Date } | null>(null)

function toggleLayout() {
  layoutMode.value = layoutMode.value === 'force' ? 'killchain' : 'force'
}

function onFilterChange(f: { severities: string[]; statuses: string[] }) {
  filters.value = f
}

// Build query params
const queryParams = computed(() => {
  const params = new URLSearchParams({ engagement_id: engId, max_nodes: '500' })
  if (filters.value.severities.length > 0 && filters.value.severities.length < 5) {
    params.set('severity', filters.value.severities.join(','))
  }
  if (filters.value.statuses.length > 0) {
    params.set('status', filters.value.statuses.join(','))
  }
  return params.toString()
})

// Fetch subgraph
const { data: subgraphData, isLoading, refetch } = useQuery({
  queryKey: ['chain-subgraph', engId, queryParams],
  queryFn: () =>
    fetch(`/api/chain/subgraph?${queryParams.value}`, { credentials: 'include' })
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch subgraph')
        return r.json()
      }),
})

const graphData = computed(() => subgraphData.value?.graph ?? { nodes: [], links: [] })
const meta = computed(() => subgraphData.value?.meta ?? { total_findings: 0, rendered_findings: 0, filtered: false, generation: 0 })
const isEmpty = computed(() => !isLoading.value && meta.value.total_findings === 0)
const hasNoRelations = computed(() => !isLoading.value && meta.value.total_findings > 0 && graphData.value.links.length === 0 && graphData.value.nodes.length === 0)

// Selection state
const selectedNode = ref<any>(null)
const selectedLink = ref<any>(null)

function onNodeClick(node: any) {
  selectedLink.value = null
  selectedNode.value = {
    ...node,
    neighborCount: graphData.value.links.filter(
      (l: any) => {
        const srcId = typeof l.source === 'string' ? l.source : l.source.id
        const tgtId = typeof l.target === 'string' ? l.target : l.target.id
        return srcId === node.id || tgtId === node.id
      }
    ).length,
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

// Curation mutation
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
    // Optimistic update: update the link in local graph data
    const link = graphData.value.links.find((l: any) => l.id === variables.relationId)
    if (link) {
      link.status = variables.status
      if (variables.status === 'user_confirmed') {
        link.drift = false
      }
    }
    if (selectedLink.value?.id === variables.relationId) {
      selectedLink.value = { ...selectedLink.value, status: variables.status }
    }
    toast.add({ severity: 'success', summary: 'Updated', detail: `Edge ${variables.status === 'user_confirmed' ? 'confirmed' : 'rejected'}`, life: 2000 })
  },
  onError: () => {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to update edge', life: 3000 })
  },
})

function onConfirm(linkId: string) {
  curateMutation.mutate({ relationId: linkId, status: 'user_confirmed' })
}

function onReject(linkId: string) {
  curateMutation.mutate({ relationId: linkId, status: 'user_rejected' })
}

// Neighborhood expansion
async function onExpand(nodeId: string) {
  try {
    const params = new URLSearchParams({
      engagement_id: engId,
      seed_finding_id: nodeId,
      hops: '2',
      max_nodes: '500',
    })
    if (filters.value.severities.length > 0 && filters.value.severities.length < 5) {
      params.set('severity', filters.value.severities.join(','))
    }
    if (filters.value.statuses.length > 0) {
      params.set('status', filters.value.statuses.join(','))
    }
    const resp = await fetch(`/api/chain/subgraph?${params}`, { credentials: 'include' })
    if (!resp.ok) throw new Error('Failed to expand')
    const expansion = await resp.json()

    // Merge into existing graph data
    const existingNodeIds = new Set(graphData.value.nodes.map((n: any) => n.id))
    const existingLinkIds = new Set(graphData.value.links.map((l: any) => l.id))

    for (const node of expansion.graph.nodes) {
      if (!existingNodeIds.has(node.id)) {
        graphData.value.nodes.push(node)
      }
    }
    for (const link of expansion.graph.links) {
      if (!existingLinkIds.has(link.id)) {
        graphData.value.links.push(link)
      }
    }

    toast.add({ severity: 'info', summary: 'Expanded', detail: `Added ${expansion.graph.nodes.length} nodes`, life: 2000 })
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to expand neighborhood', life: 3000 })
  }
}

function onRebuildComplete() {
  refetch()
}

async function onExportPath() {
  if (!selectedLink.value) return
  const srcId = typeof selectedLink.value.source === 'string' ? selectedLink.value.source : selectedLink.value.source.id
  const tgtId = typeof selectedLink.value.target === 'string' ? selectedLink.value.target : selectedLink.value.target.id

  try {
    const resp = await fetch('/api/chain/export/path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        finding_ids: [srcId, tgtId],
        engagement_id: engId,
      }),
    })
    if (!resp.ok) throw new Error('Export failed')
    const data = await resp.json()

    const blob = new Blob([data.markdown], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'attack-path-report.md'
    a.click()
    URL.revokeObjectURL(url)
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to export path', life: 3000 })
  }
}

// Engagement name for header
const { data: engagement } = useQuery({
  queryKey: ['engagement', engId],
  queryFn: () =>
    fetch(`/api/v1/engagements/${engId}`, { credentials: 'include' }).then(r => r.json()),
})
</script>

<template>
  <div class="flex flex-col h-screen">
    <!-- Toolbar -->
    <div class="flex items-center gap-3 p-3 border-b border-surface-200 dark:border-surface-700">
      <Button icon="pi pi-arrow-left" text rounded @click="router.push(`/engagements/${engId}`)" />
      <h1 class="text-lg font-bold">{{ engagement?.name ?? 'Attack Chain' }}</h1>
      <div class="flex-1">
        <ChainFilterToolbar @filter-change="onFilterChange" />
      </div>
      <Button
        :label="layoutMode === 'force' ? 'Kill Chain' : 'Force'"
        icon="pi pi-th-large"
        text size="small"
        @click="toggleLayout"
      />
    </div>

    <!-- Main content -->
    <div v-if="isLoading" class="flex-1 flex items-center justify-center">
      <ProgressSpinner />
    </div>

    <template v-else-if="isEmpty || hasNoRelations">
      <ChainEmptyState :engagement-id="engId" @rebuild-complete="onRebuildComplete" />
    </template>

    <template v-else>
      <div class="flex flex-1 overflow-hidden">
        <ForceGraphCanvas
          :data="graphData"
          :selected-node-id="selectedNode?.id ?? null"
          :selected-link-id="selectedLink?.id ?? null"
          :time-range="timeRange"
          :layout-mode="layoutMode"
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
          @expand="onExpand"
          @export-path="onExportPath"
        />
      </div>
    </template>

    <!-- Timeline scrubber -->
    <ChainTimelineScrubber
      :nodes="graphData.nodes"
      @time-range-change="(r: any) => timeRange = r"
    />

    <!-- Legend -->
    <ChainLegend
      :rendered-count="meta.rendered_findings"
      :total-count="meta.total_findings"
    />
  </div>
</template>
