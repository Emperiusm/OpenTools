<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { useRouter } from 'vue-router'
import Card from 'primevue/card'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import ProgressSpinner from 'primevue/progressspinner'

const router = useRouter()

const { data, isLoading } = useQuery({
  queryKey: ['engagements'],
  queryFn: () => fetch('/api/v1/engagements', { credentials: 'include' }).then(r => r.json()),
})
</script>

<template>
  <div>
    <div class="flex justify-between items-center mb-4">
      <h1 class="text-2xl font-bold">Engagements</h1>
      <Button label="New Engagement" icon="pi pi-plus" @click="router.push('/engagements/new')" />
    </div>

    <div v-if="isLoading" class="flex justify-center mt-8">
      <ProgressSpinner />
    </div>

    <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <Card
        v-for="eng in data?.items"
        :key="eng.id"
        class="cursor-pointer hover:border-primary transition-colors"
        @click="router.push(`/engagements/${eng.id}`)"
      >
        <template #title>{{ eng.name }}</template>
        <template #subtitle>{{ eng.target }}</template>
        <template #content>
          <div class="flex gap-2 items-center">
            <Tag
              :value="eng.status"
              :severity="eng.status === 'active' ? 'success' : 'secondary'"
            />
            <span class="text-sm text-surface-500">{{ eng.type }}</span>
          </div>
        </template>
      </Card>
    </div>

    <p
      v-if="!isLoading && (!data?.items || data.items.length === 0)"
      class="text-center text-surface-500 mt-8"
    >
      No engagements yet. Create one to get started.
    </p>
  </div>
</template>
