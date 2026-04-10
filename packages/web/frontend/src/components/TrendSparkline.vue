<script setup lang="ts">
import { computed } from 'vue'
import { Line } from 'vue-chartjs'
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Filler,
} from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler)

const props = defineProps<{ data: Record<string, number> }>()

const chartData = computed(() => {
  const months = Object.keys(props.data).sort()
  return {
    labels: months,
    datasets: [{
      data: months.map(m => props.data[m]),
      borderColor: '#10b981',
      backgroundColor: 'rgba(16, 185, 129, 0.1)',
      fill: true,
      tension: 0.3,
      borderWidth: 2,
      pointRadius: 0,
    }],
  }
})

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false }, tooltip: { enabled: false } },
  scales: { x: { display: false }, y: { display: false } },
}
</script>

<template>
  <div style="height: 40px; width: 120px;">
    <Line :data="chartData" :options="chartOptions" />
  </div>
</template>
