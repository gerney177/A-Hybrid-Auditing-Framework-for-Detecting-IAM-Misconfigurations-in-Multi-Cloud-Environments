<script setup lang="ts">
defineProps<{ items: Array<{ key: string; label: string; count?: number }> }>()
const model = defineModel<string>({ required: true })
</script>

<template>
  <div class="flex gap-1 overflow-x-auto border-b border-line" role="tablist">
    <button
      v-for="item in items"
      :key="item.key"
      role="tab"
      :aria-selected="model === item.key"
      class="relative -mb-px flex shrink-0 items-center gap-2 border-b-2 px-3.5 py-2.5 text-[13.5px] font-semibold transition-colors"
      :class="
        model === item.key ? 'border-accent text-ink' : 'border-transparent text-muted hover:text-ink'
      "
      @click="model = item.key"
    >
      {{ item.label }}
      <span
        v-if="item.count !== undefined"
        class="num rounded-full px-1.5 text-[11.5px] leading-5"
        :class="model === item.key ? 'bg-accent-soft text-accent' : 'bg-surface-2 text-muted'"
        >{{ item.count }}</span
      >
    </button>
  </div>
</template>
