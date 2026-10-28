<script setup lang="ts">
import type { Verdict } from '@/types'
import { verdictMeta } from '@/utils/labels'

withDefaults(defineProps<{ verdict: Verdict; size?: 'sm' | 'lg'; showKo?: boolean }>(), { size: 'sm', showKo: false })
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full border font-semibold tracking-wide"
    :class="size === 'lg' ? 'h-8 px-3.5 text-[13px]' : 'h-6 px-2.5 text-[11.5px]'"
    :style="{
      color: verdictMeta[verdict].var,
      background: `color-mix(in srgb, ${verdictMeta[verdict].var} 13%, transparent)`,
      borderColor: `color-mix(in srgb, ${verdictMeta[verdict].var} 32%, transparent)`,
    }"
  >
    <span class="size-1.5 rounded-full" :style="{ background: verdictMeta[verdict].var }" />
    {{ verdict }}
    <span v-if="showKo" class="font-medium opacity-80">{{ verdictMeta[verdict].ko }}</span>
  </span>
</template>
