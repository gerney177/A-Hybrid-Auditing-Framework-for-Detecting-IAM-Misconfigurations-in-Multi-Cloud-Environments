<script setup lang="ts">
import '@/charts'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'

withDefaults(defineProps<{ option: EChartsOption; height?: string }>(), { height: '280px' })
defineEmits<{ click: [params: any] }>()
</script>

<template>
  <VChart :option="option" :style="{ height }" autoresize @click="$emit('click', $event)" />
</template>
