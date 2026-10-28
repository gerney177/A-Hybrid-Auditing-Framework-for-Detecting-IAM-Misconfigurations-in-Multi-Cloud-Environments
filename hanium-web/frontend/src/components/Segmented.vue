<script setup lang="ts">
defineProps<{ options: Array<{ value: string; label: string; count?: number; color?: string }>; label?: string }>()
const model = defineModel<string>({ required: true })
</script>

<template>
  <div class="inline-flex max-w-full overflow-x-auto rounded-[10px] border border-line-strong bg-surface p-0.5" role="radiogroup" :aria-label="label">
    <button
      v-for="o in options"
      :key="o.value"
      role="radio"
      :aria-checked="model === o.value"
      class="flex h-[30px] items-center gap-1.5 rounded-[8px] px-3 text-[12.5px] font-semibold whitespace-nowrap transition-colors"
      :class="model === o.value ? 'bg-accent-soft text-accent' : 'text-muted hover:text-ink'"
      @click="model = o.value"
    >
      <span v-if="o.color" class="size-1.5 rounded-full" :style="{ background: o.color }" />
      {{ o.label }}
      <span v-if="o.count !== undefined" class="num text-[11.5px] opacity-70">{{ o.count }}</span>
    </button>
  </div>
</template>
