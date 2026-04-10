<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import Card from 'primevue/card'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'

const auth = useAuthStore()
const router = useRouter()
const toast = useToast()
const email = ref('')
const password = ref('')
const loading = ref(false)

async function handleLogin() {
  loading.value = true
  try {
    await auth.login(email.value, password.value)
    router.push('/engagements')
  } catch {
    toast.add({ severity: 'error', summary: 'Login Failed', detail: 'Invalid credentials', life: 3000 })
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="flex items-center justify-center h-screen bg-surface-ground">
    <Card class="w-96">
      <template #title>OpenTools Dashboard</template>
      <template #subtitle>Sign in to continue</template>
      <template #content>
        <div class="flex flex-col gap-3">
          <InputText v-model="email" placeholder="Email" class="w-full" @keyup.enter="handleLogin" />
          <InputText v-model="password" type="password" placeholder="Password" class="w-full" @keyup.enter="handleLogin" />
          <Button label="Sign In" :loading="loading" @click="handleLogin" class="w-full" />
        </div>
      </template>
      <template #footer>
        <p class="text-center text-sm">
          Don't have an account? <router-link to="/register" class="text-primary">Register</router-link>
        </p>
      </template>
    </Card>
  </div>
</template>
