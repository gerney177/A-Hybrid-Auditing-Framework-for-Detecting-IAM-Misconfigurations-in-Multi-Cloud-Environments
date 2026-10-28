<script setup lang="ts" generic="T extends object">
import { computed, ref, watch } from 'vue'
import Icon from './Icon.vue'
import type { Column } from './table'

const props = withDefaults(
  defineProps<{
    columns: Column<T>[]
    rows: T[]
    rowKey: (row: T) => string
    pageSize?: number
    clickable?: boolean
    emptyText?: string
    initialSort?: { key: string; dir: 'asc' | 'desc' }
  }>(),
  { pageSize: 20, emptyText: '조건에 맞는 항목이 없습니다.' },
)

const emit = defineEmits<{ rowClick: [row: T] }>()
defineSlots<Record<string, (props: { row: T; value: unknown }) => unknown>>()

const sort = ref(props.initialSort ?? null)
const page = ref(1)

function valueOf(row: T, column: Column<T>) {
  return column.sortValue ? column.sortValue(row) : ((row as Record<string, unknown>)[column.key] as number | string)
}

const sorted = computed(() => {
  const current = sort.value
  if (!current) return props.rows
  const column = props.columns.find((c) => c.key === current.key)
  if (!column) return props.rows
  const sign = current.dir === 'asc' ? 1 : -1
  return [...props.rows].sort((a, b) => {
    const x = valueOf(a, column)
    const y = valueOf(b, column)
    if (typeof x === 'number' && typeof y === 'number') return (x - y) * sign
    return String(x).localeCompare(String(y), 'ko') * sign
  })
})

const pageCount = computed(() => Math.max(1, Math.ceil(sorted.value.length / props.pageSize)))
const visible = computed(() => sorted.value.slice((page.value - 1) * props.pageSize, page.value * props.pageSize))

// 필터로 행 수가 줄어 현재 페이지가 사라지면 첫 페이지로 돌아간다.
watch(
  () => props.rows,
  () => {
    if (page.value > pageCount.value) page.value = 1
  },
)

function toggleSort(column: Column<T>) {
  if (!column.sortable) return
  const current = sort.value
  if (current?.key === column.key) sort.value = { key: column.key, dir: current.dir === 'asc' ? 'desc' : 'asc' }
  else sort.value = { key: column.key, dir: 'desc' }
  page.value = 1
}

const pages = computed(() => {
  const total = pageCount.value
  const around = new Set([1, total, page.value - 1, page.value, page.value + 1])
  const list: Array<number | '…'> = []
  let last = 0
  for (const n of [...around].filter((n) => n >= 1 && n <= total).sort((a, b) => a - b)) {
    if (n - last > 1) list.push('…')
    list.push(n)
    last = n
  }
  return list
})

const from = computed(() => (sorted.value.length === 0 ? 0 : (page.value - 1) * props.pageSize + 1))
const to = computed(() => Math.min(page.value * props.pageSize, sorted.value.length))
</script>

<template>
  <div>
    <div class="overflow-x-auto">
      <table class="w-full border-collapse text-[13.5px]">
        <thead>
          <tr>
            <th
              v-for="c in columns"
              :key="c.key"
              class="th"
              :style="{ width: c.width, textAlign: c.align ?? 'left' }"
              :aria-sort="
                sort?.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : c.sortable ? 'none' : undefined
              "
            >
              <button
                v-if="c.sortable"
                class="inline-flex items-center gap-1 font-semibold hover:text-ink"
                :class="sort?.key === c.key ? 'text-ink' : ''"
                @click="toggleSort(c)"
              >
                {{ c.label }}
                <Icon
                  :name="sort?.key === c.key ? (sort.dir === 'asc' ? 'up' : 'down') : 'sort'"
                  :size="13"
                  :class="sort?.key === c.key ? '' : 'opacity-40'"
                />
              </button>
              <template v-else>{{ c.label }}</template>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="visible.length === 0">
            <td :colspan="columns.length" class="td py-12 text-center text-muted">{{ emptyText }}</td>
          </tr>
          <tr
            v-for="row in visible"
            :key="rowKey(row)"
            class="transition-colors"
            :class="clickable ? 'cursor-pointer hover:bg-surface-2' : 'hover:bg-surface-2/60'"
            :tabindex="clickable ? 0 : undefined"
            @click="clickable && emit('rowClick', row)"
            @keydown.enter="clickable && emit('rowClick', row)"
          >
            <td v-for="c in columns" :key="c.key" class="td" :style="{ textAlign: c.align ?? 'left' }">
              <slot :name="`cell-${c.key}`" :row="row" :value="(row as Record<string, unknown>)[c.key]">
                {{ (row as Record<string, unknown>)[c.key] }}
              </slot>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="sorted.length > pageSize" class="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <span class="num text-[12.5px] text-muted">{{ from }}–{{ to }} / {{ sorted.length }}</span>
      <nav class="flex items-center gap-1" aria-label="페이지">
        <button class="btn btn-sm btn-ghost !px-2" :disabled="page === 1" aria-label="이전 페이지" @click="page--">
          <Icon name="left" :size="15" />
        </button>
        <template v-for="(p, i) in pages" :key="i">
          <span v-if="p === '…'" class="px-1 text-faint">…</span>
          <button
            v-else
            class="num h-[30px] min-w-[30px] rounded-lg px-2 text-[12.5px] font-semibold"
            :class="p === page ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-surface-2'"
            :aria-current="p === page ? 'page' : undefined"
            @click="page = p"
          >
            {{ p }}
          </button>
        </template>
        <button class="btn btn-sm btn-ghost !px-2" :disabled="page === pageCount" aria-label="다음 페이지" @click="page++">
          <Icon name="right" :size="15" />
        </button>
      </nav>
    </div>
  </div>
</template>
