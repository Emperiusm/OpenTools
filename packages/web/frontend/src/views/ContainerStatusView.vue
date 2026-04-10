<script setup lang="ts">
import { ref } from 'vue'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'

const toast = useToast()
const queryClient = useQueryClient()

// Track which (containerId, action) is currently pending to show loading per button
const pendingKey = ref<string | null>(null)

const { data, isLoading } = useQuery({
  queryKey: ['containers'],
  queryFn: () => fetch('/api/v1/containers', { credentials: 'include' }).then(r => r.json()),
  refetchInterval: 10000,
})

const actionMutation = useMutation({
  mutationFn: ({ id, action }: { id: string; action: 'start' | 'stop' | 'restart' }) =>
    fetch(`/api/v1/containers/${id}/${action}`, {
      method: 'POST',
      credentials: 'include',
    }).then(r => {
      if (!r.ok) throw new Error(`Failed to ${action}`)
      return r.json()
    }),
  onMutate: ({ id, action }) => {
    pendingKey.value = `${id}:${action}`
  },
  onSettled: () => {
    pendingKey.value = null
    queryClient.invalidateQueries({ queryKey: ['containers'] })
  },
  onSuccess: (_data, { action }) => {
    toast.add({ severity: 'success', summary: 'Done', detail: `Container ${action} succeeded`, life: 3000 })
  },
  onError: (_err, { action }) => {
    toast.add({ severity: 'error', summary: 'Error', detail: `Failed to ${action} container`, life: 3000 })
  },
})

function isPending(id: string, action: string) {
  return pendingKey.value === `${id}:${action}`
}

function stateTagSeverity(state: string): string {
  switch (state) {
    case 'running': return 'success'
    case 'stopped':
    case 'exited': return 'secondary'
    case 'paused': return 'warn'
    case 'dead':
    case 'removing': return 'danger'
    default: return 'secondary'
  }
}

function healthTagSeverity(health: string): string {
  switch (health) {
    case 'healthy': return 'success'
    case 'unhealthy': return 'danger'
    case 'starting': return 'warn'
    default: return 'secondary'
  }
}
</script>

<template>
  <div>
    <div class="flex justify-between items-center mb-4">
      <h1 class="text-2xl font-bold">Containers</h1>
      <Button
        icon="pi pi-refresh"
        label="Refresh"
        severity="secondary"
        @click="queryClient.invalidateQueries({ queryKey: ['containers'] })"
      />
    </div>

    <div v-if="isLoading" class="flex justify-center mt-8">
      <ProgressSpinner />
    </div>

    <DataTable
      v-else
      :value="data?.items ?? []"
      scrollable
      scrollHeight="flex"
      :rows="50"
      paginator
    >
      <Column field="name" header="Name" sortable />

      <Column field="state" header="State" sortable>
        <template #body="{ data: row }">
          <Tag
            :value="row.state?.toUpperCase()"
            :severity="stateTagSeverity(row.state)"
          />
        </template>
      </Column>

      <Column field="health" header="Health" sortable>
        <template #body="{ data: row }">
          <Tag
            v-if="row.health"
            :value="row.health?.toUpperCase()"
            :severity="healthTagSeverity(row.health)"
          />
          <span v-else class="text-surface-500 text-sm">—</span>
        </template>
      </Column>

      <Column field="profile" header="Profile" sortable />
      <Column field="image" header="Image" />

      <Column header="Actions">
        <template #body="{ data: row }">
          <div class="flex gap-1">
            <Button
              v-if="row.state !== 'running'"
              icon="pi pi-play"
              label="Start"
              size="small"
              severity="success"
              :loading="isPending(row.id, 'start')"
              @click="actionMutation.mutate({ id: row.id, action: 'start' })"
            />
            <Button
              v-else
              icon="pi pi-stop"
              label="Stop"
              size="small"
              severity="warn"
              :loading="isPending(row.id, 'stop')"
              @click="actionMutation.mutate({ id: row.id, action: 'stop' })"
            />
            <Button
              icon="pi pi-refresh"
              label="Restart"
              size="small"
              severity="secondary"
              :loading="isPending(row.id, 'restart')"
              @click="actionMutation.mutate({ id: row.id, action: 'restart' })"
            />
          </div>
        </template>
      </Column>
    </DataTable>

    <p
      v-if="!isLoading && (!data?.items || data.items.length === 0)"
      class="text-center text-surface-500 mt-8"
    >
      No containers found.
    </p>
  </div>
</template>
