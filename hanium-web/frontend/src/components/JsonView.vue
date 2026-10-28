<script setup lang="ts">
import { computed, ref } from 'vue'
import Icon from './Icon.vue'

const props = defineProps<{ value: unknown; maxHeight?: string }>()

const text = computed(() => JSON.stringify(props.value, null, 2) ?? '')

// 값을 HTML 로 바꾸기 전에 반드시 이스케이프한다(v-html 로 그리기 때문).
const html = computed(() =>
  text.value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
      (match) => {
        let kind = 'n'
        if (match.startsWith('"')) kind = match.endsWith(':') ? 'k' : 's'
        else if (match === 'true' || match === 'false') kind = 'b'
        else if (match === 'null') kind = 'z'
        return `<span class="j-${kind}">${match}</span>`
      },
    ),
)

const copied = ref(false)
async function copy() {
  try {
    await navigator.clipboard.writeText(text.value)
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
    <pre class="code m-0 overflow-auto p-4 pr-20" :style="{ maxHeight: maxHeight ?? '360px' }" v-html="html" />
  </div>
</template>

<style scoped>
:deep(.j-k) {
  color: var(--info);
}
:deep(.j-s) {
  color: var(--allow);
}
:deep(.j-n) {
  color: var(--alert);
}
:deep(.j-b),
:deep(.j-z) {
  color: var(--accent);
}
</style>
