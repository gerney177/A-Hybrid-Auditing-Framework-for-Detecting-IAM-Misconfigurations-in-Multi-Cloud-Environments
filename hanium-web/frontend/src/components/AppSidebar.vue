<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useTheme } from '@/composables/useTheme'
import { useAnalysis } from '@/stores/analysis'
import Icon from './Icon.vue'

const route = useRoute()
const store = useAnalysis()
const { theme, toggle } = useTheme()

const nav = [
  { to: '/', name: 'overview', label: '개요', icon: 'dashboard' },
  { to: '/identities', name: 'identities', label: '대상 목록', icon: 'users' },
  { to: '/aws', name: 'aws', label: 'AWS 정책', icon: 'shield' },
  { to: '/access', name: 'access', label: '역할 · 그룹', icon: 'key' },
]

// 상세 화면에서도 '대상 목록' 메뉴가 켜져 있도록 부모 경로를 함께 본다.
const activeName = computed(() => (route.meta.parent as string | undefined) ?? (route.name as string))
</script>

<template>
  <aside
    class="z-20 border-b border-line bg-surface lg:sticky lg:top-0 lg:flex lg:h-screen lg:flex-col lg:border-r lg:border-b-0"
  >
    <div class="flex items-center gap-3 px-5 py-4 lg:py-6">
      <div class="grid size-9 shrink-0 place-items-center rounded-[10px] bg-accent text-on-accent" style="color: var(--on-accent)">
        <Icon name="shield" :size="19" />
      </div>
      <div class="leading-tight">
        <div class="text-[15px] font-bold tracking-tight">Hanium</div>
        <div class="text-[11.5px] text-muted">IAM 위험 분석</div>
      </div>
    </div>

    <nav class="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-1 lg:flex-col lg:overflow-visible lg:pb-0" aria-label="주 메뉴">
      <RouterLink
        v-for="item in nav"
        :key="item.to"
        :to="item.to"
        class="flex shrink-0 items-center gap-3 rounded-[10px] px-3 py-2 text-[13.5px] font-semibold whitespace-nowrap transition-colors"
        :class="activeName === item.name ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2 hover:text-ink'"
        :aria-current="activeName === item.name ? 'page' : undefined"
      >
        <Icon :name="item.icon" :size="18" />
        {{ item.label }}
      </RouterLink>
    </nav>

    <div class="hidden space-y-3 border-t border-line p-4 lg:block">
      <div v-if="store.overview" class="rounded-xl bg-surface-2 px-3.5 py-3 text-[12px] leading-relaxed text-muted">
        <div class="font-semibold text-ink">Mock {{ store.overview.summary.total }}개</div>
        {{ store.overview.dataset_version }} · seed {{ store.overview.seed ?? '–' }}<br />
        실제 계정 데이터가 아닙니다
      </div>
      <button class="btn btn-sm w-full !justify-start" @click="toggle">
        <Icon :name="theme === 'dark' ? 'sun' : 'moon'" :size="15" />
        {{ theme === 'dark' ? '라이트 모드' : '다크 모드' }}
      </button>
    </div>
  </aside>
</template>
