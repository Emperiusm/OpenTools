<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Select from 'primevue/select'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const queryClient = useQueryClient()

const recipeId = route.params.id as string

const { data: recipe, isLoading: recipeLoading } = useQuery({
  queryKey: ['recipe', recipeId],
  queryFn: () =>
    fetch(`/api/v1/recipes/${recipeId}`, { credentials: 'include' }).then(r => r.json()),
})

// Engagement selector for context
const { data: engagementsData } = useQuery({
  queryKey: ['engagements'],
  queryFn: () => fetch('/api/v1/engagements', { credentials: 'include' }).then(r => r.json()),
})

const selectedEngagementId = ref<string>('')
const variableValues = ref<Record<string, string>>({})
const runOutput = ref<string | null>(null)
const runStatus = ref<'idle' | 'running' | 'success' | 'error'>('idle')

const engagementOptions = computed(() =>
  (engagementsData.value?.items ?? []).map((e: any) => ({ label: e.name, value: e.id })),
)

const runMutation = useMutation({
  mutationFn: () =>
    fetch(`/api/v1/recipes/${recipeId}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        engagement_id: selectedEngagementId.value || undefined,
        variables: variableValues.value,
      }),
      credentials: 'include',
    }).then(r => {
      if (!r.ok) throw new Error('Run failed')
      return r.json()
    }),
  onMutate: () => {
    runStatus.value = 'running'
    runOutput.value = null
  },
  onSuccess: (data) => {
    runStatus.value = 'success'
    runOutput.value = data.output ?? JSON.stringify(data, null, 2)
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    queryClient.invalidateQueries({ queryKey: ['timeline'] })
    toast.add({ severity: 'success', summary: 'Recipe ran', detail: 'Execution completed', life: 3000 })
  },
  onError: () => {
    runStatus.value = 'error'
    toast.add({ severity: 'error', summary: 'Error', detail: 'Recipe execution failed', life: 3000 })
  },
})

function getVariableInput(variable: any) {
  if (!(variable.name in variableValues.value)) {
    variableValues.value[variable.name] = variable.default ?? ''
  }
  return variableValues.value[variable.name]
}

function setVariableInput(name: string, value: string | undefined) {
  variableValues.value[name] = value ?? ''
}
</script>

<template>
  <div class="max-w-2xl mx-auto">
    <!-- Back -->
    <Button icon="pi pi-arrow-left" label="Recipes" text class="mb-4" @click="router.push('/recipes')" />

    <div v-if="recipeLoading" class="flex justify-center mt-8">
      <ProgressSpinner />
    </div>

    <div v-else-if="recipe">
      <!-- Recipe header -->
      <div class="mb-6">
        <div class="flex items-center gap-2 mb-1">
          <h1 class="text-2xl font-bold">{{ recipe.name }}</h1>
          <Tag v-if="recipe.category" :value="recipe.category" severity="secondary" />
        </div>
        <p v-if="recipe.description" class="text-surface-500">{{ recipe.description }}</p>
        <p class="text-sm text-surface-400 mt-1">
          Tool: <span class="font-medium text-surface-600">{{ recipe.tool }}</span>
        </p>
      </div>

      <!-- Engagement selector -->
      <div class="mb-4">
        <label class="block mb-1 font-medium">Engagement (optional)</label>
        <Select
          v-model="selectedEngagementId"
          :options="engagementOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="Select engagement to attach results"
          class="w-full"
          showClear
        />
      </div>

      <!-- Variable inputs -->
      <div v-if="recipe.variables?.length" class="mb-6 flex flex-col gap-4">
        <h2 class="text-lg font-semibold">Variables</h2>
        <div v-for="variable in recipe.variables" :key="variable.name">
          <label class="block mb-1 font-medium">
            {{ variable.label ?? variable.name }}
            <span v-if="variable.required" class="text-red-500 ml-1">*</span>
          </label>
          <p v-if="variable.description" class="text-xs text-surface-500 mb-1">
            {{ variable.description }}
          </p>
          <Textarea
            v-if="variable.type === 'text'"
            :modelValue="getVariableInput(variable)"
            @update:modelValue="setVariableInput(variable.name, $event)"
            :placeholder="variable.placeholder ?? variable.default ?? ''"
            class="w-full"
            rows="3"
          />
          <InputText
            v-else
            :modelValue="getVariableInput(variable)"
            @update:modelValue="setVariableInput(variable.name, $event)"
            :placeholder="variable.placeholder ?? variable.default ?? ''"
            class="w-full"
          />
        </div>
      </div>

      <!-- Run button -->
      <div class="flex gap-2 mb-6">
        <Button
          label="Run Recipe"
          icon="pi pi-play"
          :loading="runMutation.isPending.value"
          @click="runMutation.mutate()"
        />
        <Button label="Cancel" severity="secondary" @click="router.back()" />
      </div>

      <!-- Output -->
      <div v-if="runStatus !== 'idle'" class="mt-4">
        <div class="flex items-center gap-2 mb-2">
          <h2 class="text-lg font-semibold">Output</h2>
          <Tag
            v-if="runStatus === 'running'"
            value="RUNNING"
            severity="warn"
          />
          <Tag
            v-else-if="runStatus === 'success'"
            value="SUCCESS"
            severity="success"
          />
          <Tag
            v-else-if="runStatus === 'error'"
            value="ERROR"
            severity="danger"
          />
        </div>
        <div v-if="runStatus === 'running'" class="flex items-center gap-2 text-surface-500">
          <ProgressSpinner style="width: 24px; height: 24px" />
          <span>Executing…</span>
        </div>
        <pre
          v-else-if="runOutput"
          class="bg-surface-100 dark:bg-surface-800 rounded p-4 overflow-x-auto text-sm font-mono whitespace-pre-wrap max-h-96"
        >{{ runOutput }}</pre>
      </div>
    </div>

    <p v-else class="text-center text-surface-500 mt-8">Recipe not found.</p>
  </div>
</template>
