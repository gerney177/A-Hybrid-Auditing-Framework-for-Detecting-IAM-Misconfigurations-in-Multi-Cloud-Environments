<script setup lang="ts">
import { useToast } from '@/composables/useToast'
import Icon from './Icon.vue'

const { toasts, dismiss } = useToast()
const tone = {
  success: 'var(--allow)',
  error: 'var(--block)',
  info: 'var(--info)',
}
</script>

<template>
  <div class="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(420px,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
    <TransitionGroup name="fade">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="card pointer-events-auto flex items-start gap-3 px-4 py-3 text-[13px]"
        style="box-shadow: 0 12px 32px -8px rgb(0 0 0 / 0.3)"
        role="status"
      >
        <Icon :name="t.tone === 'error' ? 'warn' : 'check'" :size="17" class="mt-0.5 shrink-0" :style="{ color: tone[t.tone] }" />
        <span class="min-w-0 flex-1 break-words">{{ t.message }}</span>
        <button class="text-faint hover:text-ink" aria-label="닫기" @click="dismiss(t.id)"><Icon name="x" :size="15" /></button>
      </div>
    </TransitionGroup>
  </div>
</template>
