import { defineStore } from 'pinia'
import { ref } from 'vue'
import { useQueryClient } from '@tanstack/vue-query'

export const useSSEStore = defineStore('sse', () => {
  const connected = ref(false)
  let eventSource: EventSource | null = null

  function connect() {
    if (eventSource) return
    const queryClient = useQueryClient()
    eventSource = new EventSource('/api/v1/events', { withCredentials: true } as any)

    eventSource.onopen = () => {
      connected.value = true
      queryClient.invalidateQueries()
    }

    eventSource.onerror = () => {
      connected.value = false
    }

    eventSource.addEventListener('finding_added', () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    })

    eventSource.addEventListener('finding_updated', () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    })

    eventSource.addEventListener('container_status', () => {
      queryClient.invalidateQueries({ queryKey: ['containers'] })
    })

    eventSource.addEventListener('engagement_updated', () => {
      queryClient.invalidateQueries({ queryKey: ['engagements'] })
    })
  }

  function disconnect() {
    eventSource?.close()
    eventSource = null
    connected.value = false
  }

  return { connected, connect, disconnect }
})
