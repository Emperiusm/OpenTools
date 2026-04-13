<template>
  <div class="chain-filter-toolbar">
    <h3>Filters</h3>
    
    <div class="filter-group">
      <label>Severity</label>
      <SelectButton
        v-model="selectedSeverities"
        :options="severityOptions"
        option-label="label"
        option-value="value"
        multiple
        :allow-empty="false"
      />
    </div>
    
    <div class="filter-group">
      <label>Status</label>
      <SelectButton
        v-model="selectedStatuses"
        :options="statusOptions"
        option-label="label"
        option-value="value"
        multiple
        :allow-empty="false"
      />
    </div>
    
    <Button
      label="Reset"
      icon="pi pi-refresh"
      @click="reset"
    >
      <template #default>
        <span
          v-tooltip="'Reset filters to default'"
          class="reset-tooltip"
        >
          Reset
        </span>
      </template>
    </Button>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import SelectButton from 'primevue/selectbutton';
import Button from 'primevue/button';

const severityOptions = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
  { label: 'Info', value: 'info' }
];

const statusOptions = [
  { label: 'Confirmed', value: 'Confirmed' },
  { label: 'Candidate', value: 'Candidate' },
  { label: 'Rejected', value: 'Rejected' }
];

const selectedSeverities = ref<string[]>(['critical', 'high', 'medium']);
const selectedStatuses = ref<string[]>(['Confirmed', 'Candidate']);

const emit = defineEmits<{
  'filter-change': [payload: { selectedSeverities: string[]; selectedStatuses: string[] }]
}>();

const emitFilters = () => {
  emit('filter-change', {
    selectedSeverities: selectedSeverities.value,
    selectedStatuses: selectedStatuses.value
  });
};

watch([selectedSeverities, selectedStatuses], () => {
  emitFilters();
}, { deep: true });

const reset = () => {
  selectedSeverities.value = ['critical', 'high', 'medium'];
  selectedStatuses.value = ['Confirmed', 'Candidate'];
};
</script>

<style scoped>
.chain-filter-toolbar {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  padding: 1rem;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  background-color: #f9f9f9;
}

h3 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: #333;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.filter-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #555;
}

.reset-tooltip {
  cursor: help;
}
</style>
