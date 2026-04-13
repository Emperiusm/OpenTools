<script setup lang="ts">
import { ref, watch } from 'vue'
import SelectButton from 'primevue/selectbutton'
import Button from 'primevue/button'

const emit = defineEmits<{
  (e: 'filter-change', filters: { severities: string[]; statuses: string[] }): void
}>()

const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const statusOptions = [
  { label: 'Confirmed', value: 'auto_confirmed,user_confirmed' },
  { label: 'Candidate', value: 'candidate' },
  { label: 'Rejected', value: 'rejected,user_rejected' },
]

const selectedSeverities = ref([...severityOptions])
const selectedStatuses = ref(['auto_confirmed,user_confirmed', 'candidate'])

function emitFilters() {
  const statuses = selectedStatuses.value.flatMap(s => s.split(','))
  emit('filter-change', {
    severities: selectedSeverities.value,
    statuses,
  })
}

watch([selectedSeverities, selectedStatuses], emitFilters, { deep: true })

function reset() {
  selectedSeverities.value = [...severityOptions]
  selectedStatuses.value = ['auto_confirmed,user_confirmed', 'candidate']
}
</script>

<template>
  <div class="flex items-center gap-3 flex-wrap">
    <SelectButton
      v-model="selectedSeverities"
      :options="severityOptions"
      multiple
      :allow-empty="false"
    />
    <span class="text-surface-400">|</span>
    <SelectButton
      v-model="selectedStatuses"
      :options="statusOptions"
      option-label="label"
      option-value="value"
      multiple
      :allow-empty="false"
    />
    <Button icon="pi pi-refresh" text rounded size="small" @click="reset" v-tooltip="'Reset filters'" />
  </div>
</template>
