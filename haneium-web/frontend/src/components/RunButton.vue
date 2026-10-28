<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useAnalysis } from '@/stores/analysis'
import Icon from './Icon.vue'

const store = useAnalysis()
const open = ref(false)
const root = ref<HTMLElement | null>(null)

function onDocumentClick(event: MouseEvent) {
  if (root.value && !root.value.contains(event.target as Node)) open.value = false
}
onMounted(() => document.addEventListener('click', onDocumentClick))
onBeforeUnmount(() => document.removeEventListener('click', onDocumentClick))

async function confirm() {
  open.value = false
  await store.run()
}
</script>

<template>
  <div ref="root" class="relative">
    <button class="btn btn-primary" :disabled="store.running" @click="open = !open">
      <Icon :name="store.running ? 'spinner' : 'play'" :size="15" />
      {{ store.running ? '분석 중…' : '분석 실행·저장' }}
    </button>

    <Transition name="fade">
      <div
        v-if="open"
        class="card absolute right-0 z-30 mt-2 w-[300px] p-4"
        style="box-shadow: 0 12px 32px -8px rgb(0 0 0 / 0.28)"
        role="dialog"
        aria-label="분석 실행 확인"
      >
        <p class="text-[13px] leading-relaxed">
          Mock 300개를 처음부터 다시 분석하고 결과를 <b>DB(iam.db)에 저장</b>합니다. 실제 AWS 권한은 바뀌지 않아요.
        </p>
        <div class="mt-3 flex justify-end gap-2">
          <button class="btn btn-sm" @click="open = false">취소</button>
          <button class="btn btn-sm btn-primary" @click="confirm">실행</button>
        </div>
      </div>
    </Transition>
  </div>
</template>
