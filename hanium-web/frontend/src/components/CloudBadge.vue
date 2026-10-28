<script setup lang="ts">
import type { Cloud } from '@/types'
import { cloudDot } from '@/utils/labels'

defineProps<{ cloud: Cloud }>()
</script>

<template>
  <span class="inline-flex items-center gap-1.5 text-[12.5px] font-medium text-muted">
    <span class="size-2 rounded-[3px]" :style="{ background: cloudDot[cloud] }" />
    {{ cloud }}
  </span>
</template>
