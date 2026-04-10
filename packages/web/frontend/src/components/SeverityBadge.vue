<script setup lang="ts">
import Tag from 'primevue/tag'

const props = defineProps<{ severity: string }>()

const severityMap: Record<string, string> = {
  critical: 'danger',
  high: 'warn',
  medium: 'warn',
  low: 'info',
  info: 'secondary',
}
</script>

<template>
  <Tag :value="props.severity.toUpperCase()" :severity="severityMap[props.severity] || 'secondary'" />
</template>
