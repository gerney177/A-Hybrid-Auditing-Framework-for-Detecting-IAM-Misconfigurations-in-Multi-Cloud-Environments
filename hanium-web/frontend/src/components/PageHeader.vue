<script setup lang="ts">
defineProps<{ title: string; subtitle?: string }>()
</script>

<template>
  <header class="mb-6 flex flex-wrap items-end justify-between gap-x-6 gap-y-4">
    <div class="min-w-0">
      <h1 class="text-[26px] leading-tight font-bold tracking-tight">{{ title }}</h1>
      <p v-if="subtitle || $slots.subtitle" class="mt-1.5 text-[13.5px] text-muted">
        <slot name="subtitle">{{ subtitle }}</slot>
      </p>
    </div>
    <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2"><slot name="actions" /></div>
  </header>
</template>
