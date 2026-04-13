<script setup lang="ts">
import { ref, watch } from 'vue'
import Chip from 'primevue/chip'

interface EngagementMeta {
  id: string
  name: string
}

const props = defineProps<{
  engagements: EngagementMeta[]
}>()

const emit = defineEmits<{
  (e: 'change', engagementIds: string[]): void
}>()

const COLORS = [
  '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6',
  '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
]

const excluded = ref<Set<string>>(new Set())

function toggle(id: string) {
  const next = new Set(excluded.value)
  if (next.has(id)) {
    next.delete(id)
  } else {
    next.add(id)
  }
  excluded.value = next
}

watch(excluded, () => {
  const included = props.engagements
    .map(e => e.id)
    .filter(id => !excluded.value.has(id))
  emit('change', included)
}, { deep: true })

function colorFor(index: number): string {
  return COLORS[index % COLORS.length]
}
</script>

<template>
  <div class="flex items-center gap-2 flex-wrap">
    <span class="text-sm text-surface-400 mr-1">Engagements:</span>
    <Chip
      v-for="(eng, i) in engagements"
      :key="eng.id"
      :label="eng.name"
      class="cursor-pointer select-none"
      :class="{ 'opacity-40': excluded.has(eng.id) }"
      :style="{ borderColor: colorFor(i), borderWidth: '2px', borderStyle: 'solid' }"
      @click="toggle(eng.id)"
    >
      <template #default>
        <span
          class="inline-block w-2.5 h-2.5 rounded-full mr-1.5"
          :style="{ backgroundColor: excluded.has(eng.id) ? 'transparent' : colorFor(i) }"
        />
        <span class="text-sm">{{ eng.name }}</span>
      </template>
    </Chip>
  </div>
</template>
