<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { useUIStore } from '@/stores/ui'
import AppLayout from '@/components/AppLayout.vue'

const auth = useAuthStore()
const ui = useUIStore()

// Ensure dark mode class on load
if (ui.darkMode) {
  document.documentElement.classList.add('dark')
}
</script>

<template>
  <AppLayout v-if="auth.isAuthenticated" />
  <router-view v-else />
</template>
