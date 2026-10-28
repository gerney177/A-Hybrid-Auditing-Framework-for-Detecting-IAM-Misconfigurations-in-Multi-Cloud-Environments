<script setup lang="ts">
import { computed } from 'vue'
import type { Verdict } from '@/types'
import { verdictMeta } from '@/utils/labels'

const props = defineProps<{
  label: string
  value: string | number
  sub?: string
  tone?: Verdict
  share?: number // 0~1, 전체 대비 비율 막대
}>()

const color = computed(() => (props.tone ? verdictMeta[props.tone].var : 'var(--accent)'))
</script>

<template>
  <div class="card relative overflow-hidden p-5">
    <div class="flex items-center gap-2">
      <span class="size-2 rounded-full" :style="{ background: color }" />
      <span class="eyebrow">{{ label }}</span>
    </div>
    <div class="num mt-3 text-[34px] leading-none font-bold tracking-tight">{{ value }}</div>
    <div v-if="sub" class="mt-2 text-[12.5px] text-muted">{{ sub }}</div>
    <div v-if="share !== undefined" class="mt-4 h-1.5 overflow-hidden rounded-full bg-surface-3">
      <div
        class="h-full rounded-full transition-[width] duration-700"
        :style="{ width: `${Math.max(share * 100, share > 0 ? 2 : 0)}%`, background: color }"
      />
    </div>
  </div>
</template>
