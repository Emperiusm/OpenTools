<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { useRouter } from 'vue-router'
import Card from 'primevue/card'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import Tag from 'primevue/tag'

const router = useRouter()

const { data, isLoading } = useQuery({
  queryKey: ['recipes'],
  queryFn: () => fetch('/api/v1/recipes', { credentials: 'include' }).then(r => r.json()),
})
</script>

<template>
  <div>
    <div class="flex justify-between items-center mb-4">
      <h1 class="text-2xl font-bold">Recipes</h1>
    </div>

    <div v-if="isLoading" class="flex justify-center mt-8">
      <ProgressSpinner />
    </div>

    <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <Card v-for="recipe in data?.items" :key="recipe.id" class="flex flex-col">
        <template #title>
          <div class="flex items-center gap-2">
            <span>{{ recipe.name }}</span>
            <Tag v-if="recipe.category" :value="recipe.category" severity="secondary" />
          </div>
        </template>
        <template #subtitle>
          <span class="text-sm text-surface-500">{{ recipe.tool }}</span>
        </template>
        <template #content>
          <p class="text-sm text-surface-600 mb-4 line-clamp-3">
            {{ recipe.description ?? 'No description provided.' }}
          </p>
          <div v-if="recipe.tags?.length" class="flex flex-wrap gap-1 mb-4">
            <Tag
              v-for="tag in recipe.tags"
              :key="tag"
              :value="tag"
              severity="secondary"
              class="text-xs"
            />
          </div>
        </template>
        <template #footer>
          <Button
            label="Run"
            icon="pi pi-play"
            class="w-full"
            @click="router.push(`/recipes/${recipe.id}/run`)"
          />
        </template>
      </Card>
    </div>

    <p
      v-if="!isLoading && (!data?.items || data.items.length === 0)"
      class="text-center text-surface-500 mt-8"
    >
      No recipes available.
    </p>
  </div>
</template>
