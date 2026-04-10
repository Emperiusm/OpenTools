<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { useUIStore } from '@/stores/ui'
import { useRouter } from 'vue-router'
import Menubar from 'primevue/menubar'
import Button from 'primevue/button'
import Toast from 'primevue/toast'

const auth = useAuthStore()
const ui = useUIStore()
const router = useRouter()

const menuItems = [
  { label: 'Engagements', icon: 'pi pi-shield', command: () => router.push('/engagements') },
  { label: 'Recipes', icon: 'pi pi-play', command: () => router.push('/recipes') },
  { label: 'Containers', icon: 'pi pi-box', command: () => router.push('/containers') },
]

async function handleLogout() {
  await auth.logout()
  router.push('/login')
}
</script>

<template>
  <div class="flex flex-col h-screen">
    <Menubar :model="menuItems">
      <template #start>
        <span class="font-bold text-xl mr-4">OpenTools</span>
      </template>
      <template #end>
        <span class="mr-3 text-sm">{{ auth.user?.email }}</span>
        <Button icon="pi pi-sign-out" text rounded @click="handleLogout" />
      </template>
    </Menubar>
    <div class="flex flex-1 overflow-hidden">
      <aside v-if="ui.sidebarOpen" class="w-72 border-r border-surface-200 dark:border-surface-700 overflow-y-auto p-3">
        <slot name="sidebar">
          <!-- Sidebar content injected by views -->
        </slot>
      </aside>
      <main class="flex-1 overflow-y-auto p-4">
        <Toast />
        <router-view />
      </main>
    </div>
  </div>
</template>
