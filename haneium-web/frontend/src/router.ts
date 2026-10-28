import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'overview', component: () => import('@/views/OverviewView.vue'), meta: { title: '개요' } },
    {
      path: '/identities',
      name: 'identities',
      component: () => import('@/views/IdentitiesView.vue'),
      meta: { title: '대상 목록' },
    },
    {
      path: '/identities/:name',
      name: 'identity',
      component: () => import('@/views/IdentityDetailView.vue'),
      props: true,
      meta: { title: '대상 상세', parent: 'identities' },
    },
    { path: '/aws', name: 'aws', component: () => import('@/views/AwsView.vue'), meta: { title: 'AWS 정책' } },
    {
      path: '/access',
      name: 'access',
      component: () => import('@/views/AccessView.vue'),
      meta: { title: '역할 · 그룹' },
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
  scrollBehavior: (to, from) => (to.path === from.path ? undefined : { top: 0 }),
})

router.afterEach((to) => {
  const title = (to.meta.title as string | undefined) ?? ''
  document.title = title ? `${to.params.name ?? title} · Haneium IAM` : 'Haneium · IAM 위험 분석'
})
