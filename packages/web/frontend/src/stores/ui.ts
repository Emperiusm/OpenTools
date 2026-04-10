import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUIStore = defineStore('ui', () => {
  const sidebarOpen = ref(true)
  const darkMode = ref(localStorage.getItem('darkMode') !== 'false')

  function toggleSidebar() {
    sidebarOpen.value = !sidebarOpen.value
  }

  function toggleDarkMode() {
    darkMode.value = !darkMode.value
    localStorage.setItem('darkMode', String(darkMode.value))
    document.documentElement.classList.toggle('dark', darkMode.value)
  }

  return { sidebarOpen, darkMode, toggleSidebar, toggleDarkMode }
})
