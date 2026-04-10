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
const confirmPassword = ref('')
const loading = ref(false)

async function handleRegister() {
  if (password.value !== confirmPassword.value) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Passwords do not match', life: 3000 })
    return
  }
  loading.value = true
  try {
    await auth.register(email.value, password.value)
    toast.add({ severity: 'success', summary: 'Success', detail: 'Account created', life: 3000 })
    router.push('/login')
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Registration failed', life: 3000 })
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="flex items-center justify-center h-screen bg-surface-ground">
    <Card class="w-96">
      <template #title>Create Account</template>
      <template #content>
        <div class="flex flex-col gap-3">
          <InputText v-model="email" placeholder="Email" class="w-full" />
          <InputText v-model="password" type="password" placeholder="Password" class="w-full" />
          <InputText v-model="confirmPassword" type="password" placeholder="Confirm Password" class="w-full" />
          <Button label="Register" :loading="loading" @click="handleRegister" class="w-full" />
        </div>
      </template>
      <template #footer>
        <p class="text-center text-sm">
          Already have an account? <router-link to="/login" class="text-primary">Sign in</router-link>
        </p>
      </template>
    </Card>
  </div>
</template>
