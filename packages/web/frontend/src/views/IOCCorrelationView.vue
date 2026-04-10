<script setup lang="ts">
import { ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import ProgressSpinner from 'primevue/progressspinner'
import IOCEnrichmentCard from '@/components/IOCEnrichmentCard.vue'

const iocValue = ref('')
const searchValue = ref('')
const iocType = ref('ip')

const correlation = useQuery({
  queryKey: ['correlation', searchValue],
  queryFn: async () => {
    if (!searchValue.value) return null
    const res = await fetch(`/api/v1/iocs/correlate?value=${encodeURIComponent(searchValue.value)}`, { credentials: 'include' })
    return res.json()
  },
  enabled: () => !!searchValue.value,
})

const enrichment = useQuery({
  queryKey: ['enrichment', iocType, searchValue],
  queryFn: async () => {
    if (!searchValue.value) return null
    const res = await fetch(`/api/v1/iocs/${iocType.value}/${encodeURIComponent(searchValue.value)}/enrichment`, { credentials: 'include' })
    return res.json()
  },
  enabled: () => !!searchValue.value,
})

function search() {
  if (iocValue.value) {
    searchValue.value = iocValue.value
  }
}

async function refresh() {
  await fetch(`/api/v1/iocs/${iocType.value}/${encodeURIComponent(searchValue.value)}/enrich`, {
    method: 'POST', credentials: 'include',
  })
  await enrichment.refetch()
}
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold mb-4">IOC Correlation</h1>

    <div class="flex gap-2 mb-6">
      <InputText v-model="iocValue" placeholder="Enter IOC value (IP, domain, hash...)" class="flex-1" @keyup.enter="search" />
      <Button label="Search" icon="pi pi-search" @click="search" />
    </div>

    <div v-if="correlation.isLoading.value"><ProgressSpinner /></div>

    <div v-if="correlation.data.value && correlation.data.value.engagement_count > 0">
      <div class="mb-4 p-4 bg-surface-100 dark:bg-surface-800 rounded">
        <div class="text-lg font-bold">{{ correlation.data.value.ioc_value }}</div>
        <div class="text-surface-500">
          Type: {{ correlation.data.value.ioc_type }} ·
          {{ correlation.data.value.engagement_count }} engagements ·
          {{ correlation.data.value.total_occurrences }} occurrences ·
          Active {{ correlation.data.value.active_days }} days
        </div>
      </div>

      <h2 class="text-xl font-bold mb-2">Engagements</h2>
      <DataTable :value="correlation.data.value.engagements" class="mb-6">
        <Column field="name" header="Name" />
        <Column field="first_seen" header="First Seen" />
        <Column field="last_seen" header="Last Seen" />
      </DataTable>

      <div class="flex justify-between items-center mb-2">
        <h2 class="text-xl font-bold">Enrichment</h2>
        <Button label="Refresh" icon="pi pi-refresh" @click="refresh" />
      </div>

      <div v-if="enrichment.data.value?.aggregated_risk_score !== null" class="mb-4">
        <span class="font-bold">Aggregated Risk Score:</span>
        {{ enrichment.data.value?.aggregated_risk_score }}/100
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <IOCEnrichmentCard
          v-for="e in enrichment.data.value?.enrichments || []"
          :key="e.provider"
          :provider="e.provider"
          :risk-score="e.risk_score"
          :tags="e.tags || []"
          :confidence="e.confidence"
          :fetched-at="e.fetched_at"
          :is-stale="e.is_stale"
        />
      </div>
    </div>

    <div v-else-if="correlation.data.value && correlation.data.value.engagement_count === 0" class="text-surface-500">
      No engagements found for this IOC.
    </div>
  </div>
</template>
