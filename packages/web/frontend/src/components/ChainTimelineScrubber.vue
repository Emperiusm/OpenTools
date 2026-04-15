<script setup lang="ts">
import { ref, computed, watch, onUnmounted } from 'vue'
import Button from 'primevue/button'
import Slider from 'primevue/slider'

const props = defineProps<{
  nodes: Array<{ created_at: string | null }>
}>()

const emit = defineEmits<{
  (e: 'time-range-change', range: { start: Date; end: Date } | null): void
}>()

// Compute time bounds from nodes
const timeBounds = computed(() => {
  const timestamps = props.nodes
    .filter(n => n.created_at)
    .map(n => new Date(n.created_at!).getTime())
  if (timestamps.length === 0) return null
  return {
    min: Math.min(...timestamps),
    max: Math.max(...timestamps),
  }
})

// Slider range (0-1000 for precision)
const SLIDER_MAX = 1000
const rangeValue = ref<number[]>([0, SLIDER_MAX])

// Playing state
const playing = ref(false)
const playSpeed = ref(1)
const playTimer = ref<ReturnType<typeof setInterval> | null>(null)
const speedOptions = [1, 2, 5, 10]

// Convert slider values to dates
function sliderToDate(value: number): Date {
  if (!timeBounds.value) return new Date()
  const { min, max } = timeBounds.value
  const range = max - min || 1
  return new Date(min + (value / SLIDER_MAX) * range)
}

const currentRange = computed(() => {
  if (!timeBounds.value) return null
  return {
    start: sliderToDate(rangeValue.value[0]),
    end: sliderToDate(rangeValue.value[1]),
  }
})

const rangeLabel = computed(() => {
  if (!currentRange.value) return ''
  const fmt = (d: Date) => d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
  return `${fmt(currentRange.value.start)} \u2013 ${fmt(currentRange.value.end)}`
})

// Activity heatmap: bin node counts into segments
const HEATMAP_BINS = 50
const heatmapData = computed(() => {
  if (!timeBounds.value) return []
  const { min, max } = timeBounds.value
  const range = max - min || 1
  const bins = new Array(HEATMAP_BINS).fill(0)
  for (const n of props.nodes) {
    if (!n.created_at) continue
    const t = new Date(n.created_at).getTime()
    const idx = Math.min(Math.floor(((t - min) / range) * HEATMAP_BINS), HEATMAP_BINS - 1)
    bins[idx]++
  }
  const maxBin = Math.max(...bins, 1)
  return bins.map(b => b / maxBin)
})

watch(rangeValue, () => {
  emit('time-range-change', currentRange.value)
}, { deep: true })

function togglePlay() {
  if (playing.value) {
    stopPlay()
  } else {
    startPlay()
  }
}

function startPlay() {
  playing.value = true
  rangeValue.value = [0, rangeValue.value[1]]
  const step = Math.max(1, Math.round(SLIDER_MAX / 200))
  playTimer.value = setInterval(() => {
    const next = rangeValue.value[0] + step * playSpeed.value
    if (next >= rangeValue.value[1]) {
      rangeValue.value = [rangeValue.value[1], rangeValue.value[1]]
      stopPlay()
    } else {
      rangeValue.value = [next, rangeValue.value[1]]
    }
  }, 50)
}

function stopPlay() {
  playing.value = false
  if (playTimer.value) {
    clearInterval(playTimer.value)
    playTimer.value = null
  }
}

function reset() {
  stopPlay()
  rangeValue.value = [0, SLIDER_MAX]
  emit('time-range-change', null)
}

function cycleSpeed() {
  const idx = speedOptions.indexOf(playSpeed.value)
  playSpeed.value = speedOptions[(idx + 1) % speedOptions.length]
}

onUnmounted(() => stopPlay())
</script>

<template>
  <div v-if="timeBounds" class="flex items-center gap-3 px-4 py-2 border-t border-surface-200 dark:border-surface-700">
    <!-- Play/pause -->
    <Button
      :icon="playing ? 'pi pi-pause' : 'pi pi-play'"
      text rounded size="small"
      @click="togglePlay"
    />
    <Button
      :label="`${playSpeed}x`"
      text size="small"
      @click="cycleSpeed"
      class="w-10"
    />

    <!-- Scrubber with heatmap background -->
    <div class="flex-1 relative">
      <!-- Heatmap background -->
      <div class="absolute inset-0 flex items-end" style="height: 20px; top: -4px;">
        <div
          v-for="(intensity, i) in heatmapData"
          :key="i"
          class="flex-1"
          :style="{
            height: `${Math.max(intensity * 100, 5)}%`,
            backgroundColor: `rgba(59, 130, 246, ${0.1 + intensity * 0.4})`,
          }"
        />
      </div>
      <!-- Slider -->
      <Slider
        v-model="rangeValue"
        range
        :min="0"
        :max="SLIDER_MAX"
        class="relative z-10"
      />
    </div>

    <!-- Time label -->
    <span class="text-xs text-surface-400 whitespace-nowrap min-w-48 text-right">
      {{ rangeLabel }}
    </span>

    <!-- Reset -->
    <Button icon="pi pi-refresh" text rounded size="small" @click="reset" v-tooltip="'Show all'" />
  </div>
</template>
