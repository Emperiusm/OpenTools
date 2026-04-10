<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useQuery } from '@tanstack/vue-query'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import TrendSparkline from '@/components/TrendSparkline.vue'

const router = useRouter()
const days = ref(30)
const limit = ref(10)

const daysOptions = [7, 30, 90, 180, 365]
const limitOptions = [10, 25, 50]

const trending = useQuery({
  queryKey: ['trending', days, limit],
  queryFn: async () => {
    const res = await fetch(`/api/v1/iocs/trending?days=${days.value}&limit=${limit.value}`, { credentials: 'include' })
    return res.json()
  },
})

function trendColor(trend: string) {
  return { rising: 'danger', declining: 'info', stable: 'secondary' }[trend] || 'secondary'
}

function onRowClick(event: any) {
  router.push(`/iocs/correlate?value=${encodeURIComponent(event.data.ioc_value)}`)
}
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold mb-4">Trending IOCs</h1>

    <div class="flex gap-4 mb-4">
      <div>
        <label class="block text-sm mb-1">Timeframe (days)</label>
        <Select v-model="days" :options="daysOptions" />
      </div>
      <div>
        <label class="block text-sm mb-1">Limit</label>
        <Select v-model="limit" :options="limitOptions" />
      </div>
    </div>

    <DataTable :value="trending.data.value || []" :loading="trending.isLoading.value" @row-click="onRowClick">
      <Column field="ioc_type" header="Type" />
      <Column field="ioc_value" header="Value" />
      <Column field="engagement_count" header="Engagements" />
      <Column field="total_occurrences" header="Occurrences" />
      <Column header="Trend">
        <template #body="{ data }">
          <Tag :value="data.trend" :severity="trendColor(data.trend)" />
        </template>
      </Column>
      <Column header="Activity">
        <template #body="{ data }">
          <TrendSparkline :data="data.frequency_by_month || {}" />
        </template>
      </Column>
    </DataTable>
  </div>
</template>
