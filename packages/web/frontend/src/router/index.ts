import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue') },
    { path: '/register', name: 'register', component: () => import('@/views/RegisterView.vue') },
    { path: '/', redirect: '/engagements' },
    { path: '/engagements', name: 'engagements', component: () => import('@/views/EngagementListView.vue') },
    { path: '/engagements/new', name: 'engagement-create', component: () => import('@/views/EngagementCreateView.vue') },
    { path: '/engagements/:id', name: 'engagement-detail', component: () => import('@/views/EngagementDetailView.vue') },
    { path: '/findings/:id', name: 'finding-detail', component: () => import('@/views/FindingDetailView.vue') },
    { path: '/recipes', name: 'recipes', component: () => import('@/views/RecipeListView.vue') },
    { path: '/recipes/:id/run', name: 'recipe-run', component: () => import('@/views/RecipeRunnerView.vue') },
    { path: '/containers', name: 'containers', component: () => import('@/views/ContainerStatusView.vue') },
    { path: '/iocs/correlate', name: 'ioc-correlate', component: () => import('@/views/IOCCorrelationView.vue') },
    { path: '/iocs/trending', name: 'ioc-trending', component: () => import('@/views/IOCTrendingView.vue') },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  const publicPages = ['/login', '/register']
  if (!publicPages.includes(to.path) && !auth.isAuthenticated) {
    await auth.fetchUser()
    if (!auth.isAuthenticated) {
      return '/login'
    }
  }
})

export default router
