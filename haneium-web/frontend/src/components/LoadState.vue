<script setup lang="ts">
import Icon from './Icon.vue'

// 화면 전체의 로딩·오류·빈 상태를 한 곳에서 처리한다.
defineProps<{ loading?: boolean; error?: string | null; empty?: boolean; emptyText?: string }>()
defineEmits<{ retry: [] }>()
</script>

<template>
  <div v-if="loading" class="space-y-4" aria-busy="true" aria-label="불러오는 중">
    <div class="grid grid-cols-2 gap-4 xl:grid-cols-4">
      <div v-for="n in 4" :key="n" class="skeleton h-[128px]" />
    </div>
    <div class="skeleton h-[320px]" />
  </div>

  <div v-else-if="error" class="card mx-auto mt-10 max-w-lg p-8 text-center">
    <div
      class="mx-auto mb-4 grid size-12 place-items-center rounded-full"
      style="background: color-mix(in srgb, var(--block) 12%, transparent); color: var(--block)"
    >
      <Icon name="warn" :size="22" />
    </div>
    <h2 class="text-base font-semibold">데이터를 불러오지 못했어요</h2>
    <p class="mt-2 text-[13.5px] break-words text-muted">{{ error }}</p>
    <button class="btn btn-primary mt-5" @click="$emit('retry')">다시 시도</button>
  </div>

  <div v-else-if="empty" class="card mx-auto mt-10 max-w-lg p-8 text-center">
    <p class="text-[13.5px] text-muted">{{ emptyText ?? '표시할 데이터가 없습니다.' }}</p>
    <div v-if="$slots.empty" class="mt-4"><slot name="empty" /></div>
  </div>

  <slot v-else />
</template>
