<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useMutation, useQueryClient } from '@tanstack/vue-query'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'

const router = useRouter()
const toast = useToast()
const queryClient = useQueryClient()

const name = ref('')
const target = ref('')
const type = ref('pentest')
const scope = ref('')

const types = [
  'pentest',
  'reverse-engineering',
  'hardware-re',
  'forensics',
  'cloud-security',
  'mobile',
  'combined',
]

const mutation = useMutation({
  mutationFn: () =>
    fetch('/api/v1/engagements', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name.value,
        target: target.value,
        type: type.value,
        scope: scope.value || undefined,
      }),
      credentials: 'include',
    }).then(r => {
      if (!r.ok) throw new Error('Failed')
      return r.json()
    }),
  onSuccess: (data) => {
    queryClient.invalidateQueries({ queryKey: ['engagements'] })
    toast.add({
      severity: 'success',
      summary: 'Created',
      detail: `Engagement "${name.value}" created`,
      life: 3000,
    })
    router.push(`/engagements/${data.id}`)
  },
  onError: () =>
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to create engagement',
      life: 3000,
    }),
})
</script>

<template>
  <div class="max-w-lg mx-auto">
    <h1 class="text-2xl font-bold mb-4">New Engagement</h1>
    <div class="flex flex-col gap-4">
      <div>
        <label class="block mb-1 font-medium">Name *</label>
        <InputText v-model="name" placeholder="my-pentest" class="w-full" />
      </div>
      <div>
        <label class="block mb-1 font-medium">Target *</label>
        <InputText v-model="target" placeholder="192.168.1.0/24" class="w-full" />
      </div>
      <div>
        <label class="block mb-1 font-medium">Type</label>
        <Select v-model="type" :options="types" class="w-full" />
      </div>
      <div>
        <label class="block mb-1 font-medium">Scope</label>
        <InputText v-model="scope" placeholder="Optional scope description" class="w-full" />
      </div>
      <div class="flex gap-2">
        <Button
          label="Create"
          :loading="mutation.isPending.value"
          :disabled="!name || !target"
          @click="mutation.mutate()"
        />
        <Button label="Cancel" severity="secondary" @click="router.back()" />
      </div>
    </div>
  </div>
</template>
