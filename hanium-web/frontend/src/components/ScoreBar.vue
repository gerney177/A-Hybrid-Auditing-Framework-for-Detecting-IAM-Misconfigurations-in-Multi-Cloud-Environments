<script setup lang="ts">
import { computed } from 'vue'
import type { Verdict } from '@/types'
import { verdictMeta } from '@/utils/labels'

const props = withDefaults(
  defineProps<{ value: number; verdict?: Verdict; width?: number; digits?: number; muted?: boolean }>(),
  { width: 72, digits: 3 },
)

const color = computed(() => (props.verdict ? verdictMeta[props.verdict].var : 'var(--accent)'))
</script>

<template>
  <span class="inline-flex items-center gap-2.5">
    <span class="h-1.5 overflow-hidden rounded-full bg-surface-3" :style="{ width: `${width}px` }">
      <span
        class="block h-full rounded-full"
        :style="{ width: `${Math.min(Math.max(value, 0), 1) * 100}%`, background: muted ? 'var(--faint)' : color }"
      />
    </span>
    <span class="num min-w-[38px] text-[13px]" :class="muted ? 'text-muted' : 'font-semibold'">{{
      value.toFixed(digits)
    }}</span>
  </span>
</template>
