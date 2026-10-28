<script setup lang="ts">
import Icon from './Icon.vue'

withDefaults(defineProps<{ tone?: 'info' | 'warn' }>(), { tone: 'info' })
</script>

<template>
  <div
    class="flex items-start gap-3 rounded-xl border px-4 py-3 text-[13px] leading-relaxed"
    :style="{
      color: 'var(--text)',
      background: `color-mix(in srgb, ${tone === 'warn' ? 'var(--alert)' : 'var(--info)'} 9%, var(--surface))`,
      borderColor: `color-mix(in srgb, ${tone === 'warn' ? 'var(--alert)' : 'var(--info)'} 28%, var(--border))`,
    }"
  >
    <Icon
      :name="tone === 'warn' ? 'warn' : 'info'"
      :size="17"
      class="mt-0.5 shrink-0"
      :style="{ color: tone === 'warn' ? 'var(--alert)' : 'var(--info)' }"
    />
    <div><slot /></div>
  </div>
</template>
