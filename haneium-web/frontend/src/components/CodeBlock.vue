<script setup lang="ts">
import { ref } from 'vue'
import Icon from './Icon.vue'

const props = defineProps<{ code: string; maxHeight?: string }>()

const copied = ref(false)
async function copy() {
  try {
    await navigator.clipboard.writeText(props.code)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {
    /* 클립보드를 못 쓰는 환경에서는 조용히 넘어간다 */
  }
}
</script>

<template>
  <div class="relative rounded-xl border border-line bg-surface-2">
    <button class="btn btn-sm btn-ghost absolute top-2 right-2 !h-7" @click="copy">
      <Icon :name="copied ? 'check' : 'copy'" :size="14" />
      {{ copied ? '복사됨' : '복사' }}
    </button>
    <pre class="code m-0 overflow-auto p-4 pr-20" :style="{ maxHeight: maxHeight ?? '320px' }">{{ code }}</pre>
  </div>
</template>
