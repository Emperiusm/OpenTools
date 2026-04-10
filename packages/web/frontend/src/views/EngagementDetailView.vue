<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dialog from 'primevue/dialog'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'
import SeverityBadge from '@/components/SeverityBadge.vue'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const queryClient = useQueryClient()

const engId = route.params.id as string
const deleteDialogVisible = ref(false)

// Engagement summary
const { data: engagement, isLoading: engLoading } = useQuery({
  queryKey: ['engagement', engId],
  queryFn: () =>
    fetch(`/api/v1/engagements/${engId}`, { credentials: 'include' }).then(r => r.json()),
})

// Findings
const { data: findingsData, isLoading: findingsLoading } = useQuery({
  queryKey: ['findings', engId],
  queryFn: () =>
    fetch(`/api/v1/engagements/${engId}/findings`, { credentials: 'include' }).then(r => r.json()),
})

// Timeline
const { data: timelineData, isLoading: timelineLoading } = useQuery({
  queryKey: ['timeline', engId],
  queryFn: () =>
    fetch(`/api/v1/engagements/${engId}/timeline`, { credentials: 'include' }).then(r => r.json()),
})

// IOCs
const { data: iocsData, isLoading: iocsLoading } = useQuery({
  queryKey: ['iocs', engId],
  queryFn: () =>
    fetch(`/api/v1/engagements/${engId}/iocs`, { credentials: 'include' }).then(r => r.json()),
})

// Artifacts
const { data: artifactsData, isLoading: artifactsLoading } = useQuery({
  queryKey: ['artifacts', engId],
  queryFn: () =>
    fetch(`/api/v1/engagements/${engId}/artifacts`, { credentials: 'include' }).then(r =>
      r.json(),
    ),
})

const deleteMutation = useMutation({
  mutationFn: () =>
    fetch(`/api/v1/engagements/${engId}`, {
      method: 'DELETE',
      credentials: 'include',
    }).then(r => {
      if (!r.ok) throw new Error('Failed to delete')
      return r
    }),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['engagements'] })
    toast.add({ severity: 'success', summary: 'Deleted', detail: 'Engagement deleted', life: 3000 })
    router.push('/engagements')
  },
  onError: () =>
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete engagement', life: 3000 }),
})

const severityCounts = computed(() => {
  const findings = findingsData.value?.items ?? []
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) {
    if (f.severity in counts) counts[f.severity]++
  }
  return counts
})

function formatDate(dateStr: string) {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleString()
}
</script>

<template>
  <div>
    <!-- Header -->
    <div class="flex justify-between items-start mb-4">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <Button icon="pi pi-arrow-left" text rounded @click="router.push('/engagements')" />
          <h1 class="text-2xl font-bold">
            {{ engLoading ? 'Loading…' : engagement?.name ?? 'Engagement' }}
          </h1>
          <Tag
            v-if="engagement"
            :value="engagement.status"
            :severity="engagement.status === 'active' ? 'success' : 'secondary'"
          />
        </div>
        <p v-if="engagement" class="text-surface-500 ml-10">
          {{ engagement.target }} &bull; {{ engagement.type }}
        </p>
      </div>
      <Button
        label="Delete"
        icon="pi pi-trash"
        severity="danger"
        outlined
        @click="deleteDialogVisible = true"
      />
    </div>

    <!-- Severity summary strip -->
    <div v-if="!findingsLoading && findingsData" class="flex gap-3 mb-4 flex-wrap">
      <div
        v-for="(count, sev) in severityCounts"
        :key="sev"
        class="flex items-center gap-1"
      >
        <SeverityBadge :severity="sev" />
        <span class="text-sm font-semibold">{{ count }}</span>
      </div>
    </div>

    <div v-if="engLoading" class="flex justify-center mt-8">
      <ProgressSpinner />
    </div>

    <!-- Tabs -->
    <TabView v-else>
      <!-- Findings Tab -->
      <TabPanel value="findings" header="Findings">
        <div v-if="findingsLoading" class="flex justify-center mt-4">
          <ProgressSpinner />
        </div>
        <DataTable
          v-else
          :value="findingsData?.items ?? []"
          sortField="severity"
          :sortOrder="1"
          scrollable
          scrollHeight="flex"
          :rows="50"
          paginator
          rowHover
          @row-click="(e) => router.push(`/findings/${e.data.id}`)"
        >
          <Column field="title" header="Title" sortable />
          <Column field="severity" header="Severity" sortable>
            <template #body="{ data }">
              <SeverityBadge :severity="data.severity" />
            </template>
          </Column>
          <Column field="status" header="Status" sortable>
            <template #body="{ data }">
              <Tag
                :value="data.status"
                :severity="
                  data.status === 'confirmed'
                    ? 'danger'
                    : data.status === 'false_positive'
                    ? 'secondary'
                    : 'warn'
                "
              />
            </template>
          </Column>
          <Column field="tool" header="Tool" sortable />
          <Column field="phase" header="Phase" sortable />
          <Column header="">
            <template #body="{ data }">
              <Button
                icon="pi pi-arrow-right"
                text
                rounded
                @click.stop="router.push(`/findings/${data.id}`)"
              />
            </template>
          </Column>
        </DataTable>
        <p v-if="!findingsLoading && (!findingsData?.items || findingsData.items.length === 0)" class="text-center text-surface-500 mt-4">
          No findings yet.
        </p>
      </TabPanel>

      <!-- Timeline Tab -->
      <TabPanel value="timeline" header="Timeline">
        <div v-if="timelineLoading" class="flex justify-center mt-4">
          <ProgressSpinner />
        </div>
        <DataTable
          v-else
          :value="timelineData?.items ?? []"
          sortField="timestamp"
          :sortOrder="-1"
          scrollable
          scrollHeight="flex"
          :rows="50"
          paginator
        >
          <Column field="timestamp" header="Time" sortable>
            <template #body="{ data }">{{ formatDate(data.timestamp) }}</template>
          </Column>
          <Column field="event_type" header="Event" sortable />
          <Column field="summary" header="Summary" />
          <Column field="tool" header="Tool" sortable />
        </DataTable>
        <p v-if="!timelineLoading && (!timelineData?.items || timelineData.items.length === 0)" class="text-center text-surface-500 mt-4">
          No timeline events yet.
        </p>
      </TabPanel>

      <!-- IOCs Tab -->
      <TabPanel value="iocs" header="IOCs">
        <div v-if="iocsLoading" class="flex justify-center mt-4">
          <ProgressSpinner />
        </div>
        <DataTable
          v-else
          :value="iocsData?.items ?? []"
          scrollable
          scrollHeight="flex"
          :rows="50"
          paginator
        >
          <Column field="type" header="Type" sortable />
          <Column field="value" header="Value" sortable />
          <Column field="context" header="Context" />
          <Column field="confidence" header="Confidence" sortable />
        </DataTable>
        <p v-if="!iocsLoading && (!iocsData?.items || iocsData.items.length === 0)" class="text-center text-surface-500 mt-4">
          No IOCs recorded yet.
        </p>
      </TabPanel>

      <!-- Artifacts Tab -->
      <TabPanel value="artifacts" header="Artifacts">
        <div v-if="artifactsLoading" class="flex justify-center mt-4">
          <ProgressSpinner />
        </div>
        <div v-else>
          <ul v-if="artifactsData?.items?.length" class="flex flex-col gap-2 mt-2">
            <li
              v-for="artifact in artifactsData.items"
              :key="artifact.id"
              class="flex items-center gap-3 p-3 border border-surface-200 rounded"
            >
              <i class="pi pi-file text-surface-500" />
              <div class="flex-1">
                <p class="font-medium">{{ artifact.name }}</p>
                <p class="text-sm text-surface-500">{{ artifact.path }}</p>
              </div>
              <span class="text-sm text-surface-500">{{ formatDate(artifact.created_at) }}</span>
            </li>
          </ul>
          <p v-else class="text-center text-surface-500 mt-4">No artifacts yet.</p>
        </div>
      </TabPanel>
    </TabView>

    <!-- Delete Confirmation Dialog -->
    <Dialog
      v-model:visible="deleteDialogVisible"
      header="Delete Engagement"
      modal
      :style="{ width: '30rem' }"
    >
      <p>
        Are you sure you want to delete
        <strong>{{ engagement?.name }}</strong>? This action cannot be undone.
      </p>
      <template #footer>
        <Button label="Cancel" severity="secondary" @click="deleteDialogVisible = false" />
        <Button
          label="Delete"
          severity="danger"
          :loading="deleteMutation.isPending.value"
          @click="deleteMutation.mutate()"
        />
      </template>
    </Dialog>
  </div>
</template>
