<script setup lang="ts">
import type { EChartsOption } from 'echarts'
import { computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, downloads } from '@/api/client'
import BaseChart from '@/components/BaseChart.vue'
import CloudBadge from '@/components/CloudBadge.vue'
import DataTable from '@/components/DataTable.vue'
import Icon from '@/components/Icon.vue'
import KpiCard from '@/components/KpiCard.vue'
import LoadState from '@/components/LoadState.vue'
import Notice from '@/components/Notice.vue'
import PageHeader from '@/components/PageHeader.vue'
import RunButton from '@/components/RunButton.vue'
import ScoreBar from '@/components/ScoreBar.vue'
import VerdictBadge from '@/components/VerdictBadge.vue'
import type { Column } from '@/components/table'
import { useFetch } from '@/composables/useFetch'
import { usePalette } from '@/composables/useTheme'
import { useAnalysis } from '@/stores/analysis'
import type { RunRecord, Verdict } from '@/types'
import { chartBase, verdictColors } from '@/utils/chart'
import { formatNumber, kst, percent, score } from '@/utils/format'
import { decisionMeta, reasonLabel, remediationMeta, VERDICTS } from '@/utils/labels'

const store = useAnalysis()
const router = useRouter()
const palette = usePalette()

const o = computed(() => store.overview)

// 조치 효과가 큰 순서. 분석을 다시 실행하면(store.version) 새로 불러온다.
const { data: fixes, reload: reloadFixes } = useFetch(() => api.remediations())
watch(() => store.version, reloadFixes, { immediate: true })
const topFixes = computed(() =>
  [...(fixes.value ?? [])]
    .filter((p) => p.effect?.remediation_applied)
    .sort((a, b) => b.effect!.risk_reduction - a.effect!.risk_reduction)
    .slice(0, 5),
)
const count = (v: Verdict) => o.value?.summary.verdicts[v] ?? 0
const total = computed(() => o.value?.summary.total ?? 0)

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)

// 판정 분포(도넛)
const donut = computed<EChartsOption>(() => {
  const p = palette.value
  const colors = verdictColors(p)
  const base = chartBase(p)
  return {
    ...base,
    tooltip: { ...base.tooltip, trigger: 'item', formatter: '{b} · {c}개 ({d}%)' },
    series: [
      {
        type: 'pie',
        radius: ['64%', '88%'],
        label: { show: false },
        itemStyle: { borderColor: p.surface, borderWidth: 3, borderRadius: 6 },
        emphasis: { scale: false },
        data: VERDICTS.map((v) => ({ name: v, value: count(v), itemStyle: { color: colors[v] } })),
      },
    ],
  }
})

// 클라우드별 판정(가로 누적 막대)
const byCloud = computed<EChartsOption>(() => {
  const p = palette.value
  const colors = verdictColors(p)
  const data = o.value?.verdict_by_cloud ?? {}
  const clouds = Object.keys(data)
  return {
    ...chartBase(p),
    tooltip: { ...chartBase(p).tooltip, trigger: 'axis', axisPointer: { type: 'shadow', shadowStyle: { color: `${p.muted}14` } } },
    legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 10, icon: 'roundRect', textStyle: { color: p.muted } },
    grid: { left: 4, right: 12, top: 34, bottom: 4, containLabel: true },
    xAxis: { type: 'value', splitLine: { lineStyle: { color: p.border } }, axisLabel: { color: p.faint } },
    yAxis: { type: 'category', inverse: true, data: clouds, axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: p.text, fontWeight: 600, fontSize: 13 } },
    series: VERDICTS.map((v) => ({
      name: v,
      type: 'bar' as const,
      stack: 'total',
      barWidth: 26,
      itemStyle: { color: colors[v] },
      label: {
        show: true,
        color: '#fff',
        fontWeight: 600,
        formatter: (item: { value?: unknown }) => (Number(item.value) >= 6 ? String(item.value) : ''),
      },
      data: clouds.map((c) => (data as Record<string, Record<Verdict, number>>)[c][v]),
    })),
  }
})

// 위험 점수 순위: 300개를 점수 순으로 세워 두면 꼬리가 길다는 게 한눈에 보인다.
const ranked = computed(() => [...store.identities].sort((a, b) => a.rank - b.rank))
const rankChart = computed<EChartsOption>(() => {
  const p = palette.value
  const colors = verdictColors(p)
  const rows = ranked.value
  return {
    ...chartBase(p),
    tooltip: {
      ...chartBase(p).tooltip,
      trigger: 'item',
      formatter: (item: any) => {
        const r = rows[item.dataIndex]
        return `<b>${esc(r.name)}</b> · ${esc(r.cloud)}<br/>${r.verdict} · 위험 점수 ${r.risk_score.toFixed(3)}<br/><span style="color:${p.faint}">${r.rank}위 / ${rows.length}</span>`
      },
    },
    grid: { left: 4, right: 8, top: 12, bottom: 22, containLabel: true },
    xAxis: {
      type: 'category',
      data: rows.map((r) => r.name),
      axisLabel: { show: false },
      axisTick: { show: false },
      axisLine: { lineStyle: { color: p.border } },
      name: '← 위험 높음 · 위험 점수 순위 · 낮음 →',
      nameLocation: 'middle',
      nameGap: 8,
      nameTextStyle: { color: p.faint, fontSize: 11.5 },
    },
    yAxis: { type: 'value', min: 0, max: 1, interval: 0.25, splitLine: { lineStyle: { color: p.border } }, axisLabel: { color: p.faint } },
    series: [
      {
        type: 'bar',
        barCategoryGap: '12%',
        data: rows.map((r) => ({ value: r.risk_score, itemStyle: { color: colors[r.verdict], borderRadius: [2, 2, 0, 0] } })),
        emphasis: { itemStyle: { opacity: 0.85 } },
      },
    ],
  }
})

const reasonChart = computed<EChartsOption>(() => {
  const p = palette.value
  const list = o.value?.reasons ?? []
  return {
    ...chartBase(p),
    tooltip: { ...chartBase(p).tooltip, trigger: 'axis', axisPointer: { type: 'none' } },
    grid: { left: 4, right: 36, top: 4, bottom: 4, containLabel: true },
    xAxis: { type: 'value', show: false },
    yAxis: { type: 'category', inverse: true, data: list.map((r) => reasonLabel(r.code)), axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: p.text, fontSize: 12.5 } },
    series: [
      {
        type: 'bar',
        barWidth: 14,
        data: list.map((r) => r.count),
        itemStyle: { color: p.accent, borderRadius: 4 },
        label: { show: true, position: 'right', color: p.muted, fontWeight: 600 },
      },
    ],
  }
})

const remediation = computed(() => o.value?.remediation)
const afterChart = computed<EChartsOption>(() => {
  const p = palette.value
  const colors = verdictColors(p)
  const after = remediation.value?.after_verdicts ?? {}
  return {
    ...chartBase(p),
    tooltip: { ...chartBase(p).tooltip, trigger: 'axis', axisPointer: { type: 'shadow', shadowStyle: { color: `${p.muted}14` } } },
    grid: { left: 4, right: 12, top: 8, bottom: 4, containLabel: true },
    xAxis: { type: 'value', show: false, max: total.value },
    yAxis: { type: 'category', inverse: true, data: ['현재', '개선 후'], axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: p.text, fontWeight: 600 } },
    series: VERDICTS.map((v) => ({
      name: v,
      type: 'bar' as const,
      stack: 'total',
      barWidth: 22,
      itemStyle: { color: colors[v] },
      label: { show: true, color: '#fff', fontWeight: 600, formatter: (item: { value?: unknown }) => (Number(item.value) >= 12 ? String(item.value) : '') },
      data: [count(v), after[v] ?? 0],
    })),
  }
})

const decisionRows = computed(() => {
  const d = o.value?.decision_by ?? {}
  const max = Math.max(...Object.values(d), 1)
  return (Object.keys(decisionMeta) as Array<keyof typeof decisionMeta>)
    .map((k) => ({ key: k, count: d[k] ?? 0, width: ((d[k] ?? 0) / max) * 100, ...decisionMeta[k] }))
    .sort((a, b) => b.count - a.count)
})

const runColumns: Column<RunRecord>[] = [
  { key: 'run_id', label: '실행 ID', sortable: true, width: '110px' },
  { key: 'dataset_id', label: '데이터 ID', sortable: true, width: '110px' },
  { key: 'created_at', label: '저장 시각 (KST)', sortable: true },
  { key: 'source', label: '입력 출처' },
]

const stamp = computed(() => (o.value ? kst(o.value.executed_at) : ''))
</script>

<template>
  <div>
  <LoadState :loading="store.loading && !o" :error="store.error" :empty="store.missing" empty-text="저장된 분석 결과가 아직 없습니다." @retry="store.load()">
    <template #empty><RunButton /></template>

    <template v-if="o">
      <PageHeader title="개요">
        <template #subtitle>
          마지막 분석 <span class="num">{{ stamp }}</span> (한국 시간) · 실행 ID {{ o.run_id ?? '–' }} · {{ o.dataset_version }}
        </template>
        <template #actions>
          <a class="btn" :href="downloads.csv" download><Icon name="download" :size="15" />CSV</a>
          <a class="btn" :href="downloads.report" download><Icon name="download" :size="15" />JSON</a>
          <RunButton />
        </template>
      </PageHeader>

      <Notice class="mb-5">
        AWS·Azure·GCP 각 100개, 총 {{ formatNumber(total) }}개의 <b>Mock 데이터</b>를 분석한 결과예요. 실제 계정의 안전성이나 탐지 정확도를 보증하지 않습니다.
      </Notice>

      <section class="grid grid-cols-2 gap-4 xl:grid-cols-4" aria-label="요약">
        <KpiCard label="분석 대상" :value="formatNumber(total)" :sub="Object.entries(o.summary.clouds).map(([k, v]) => `${k} ${v}`).join(' · ')" />
        <KpiCard label="BLOCK · 차단" :value="count('BLOCK')" tone="BLOCK" :sub="`전체의 ${percent(count('BLOCK'), total)}`" :share="count('BLOCK') / total" />
        <KpiCard label="ALERT · 경고" :value="count('ALERT')" tone="ALERT" :sub="`전체의 ${percent(count('ALERT'), total)}`" :share="count('ALERT') / total" />
        <KpiCard label="ALLOW · 허용" :value="count('ALLOW')" tone="ALLOW" :sub="`전체의 ${percent(count('ALLOW'), total)}`" :share="count('ALLOW') / total" />
      </section>

      <section class="mt-4 grid gap-4 lg:grid-cols-5">
        <div class="card card-pad lg:col-span-2">
          <h2 class="h-card">판정 분포</h2>
          <div class="mt-4 flex flex-wrap items-center justify-center gap-x-6 gap-y-4 sm:justify-start">
            <div class="relative size-[176px] shrink-0">
              <BaseChart :option="donut" height="176px" />
              <div class="pointer-events-none absolute inset-0 grid place-items-center text-center">
                <div>
                  <div class="num text-[28px] leading-none font-bold">{{ formatNumber(total) }}</div>
                  <div class="mt-1 text-[11.5px] text-muted">전체 대상</div>
                </div>
              </div>
            </div>
            <ul class="min-w-[160px] flex-1 space-y-3">
              <li v-for="v in VERDICTS" :key="v" class="flex items-center justify-between gap-3 text-[13px]">
                <VerdictBadge :verdict="v" />
                <span class="num text-right">
                  <b>{{ count(v) }}</b>
                  <span class="ml-1.5 text-muted">{{ percent(count(v), total) }}</span>
                </span>
              </li>
            </ul>
          </div>
        </div>

        <div class="card card-pad lg:col-span-3">
          <h2 class="h-card">클라우드별 판정</h2>
          <p class="mt-0.5 text-[12.5px] text-muted">클라우드마다 BLOCK·ALERT·ALLOW 개수를 비교합니다.</p>
          <BaseChart :option="byCloud" height="168px" />
        </div>
      </section>

      <section class="card card-pad mt-4">
        <div class="flex flex-wrap items-baseline justify-between gap-2">
          <h2 class="h-card">위험 점수 순위</h2>
          <div class="flex items-center gap-4 text-[12px] text-muted">
            <span v-for="v in VERDICTS" :key="v" class="inline-flex items-center gap-1.5">
              <span class="size-2 rounded-[3px]" :style="{ background: verdictColors(palette)[v] }" />{{ v }}
            </span>
            <span class="hidden sm:inline text-faint">막대를 누르면 상세 화면으로 이동해요</span>
          </div>
        </div>
        <BaseChart :option="rankChart" height="240px" @click="(e) => router.push(`/identities/${encodeURIComponent(e.name)}`)" />
      </section>

      <section class="mt-4 grid gap-4 lg:grid-cols-2">
        <div class="card card-pad">
          <h2 class="h-card">판정 근거</h2>
          <p class="mt-0.5 text-[12.5px] text-muted">경고·차단된 대상에 붙은 근거 코드를 센 결과입니다.</p>
          <BaseChart :option="reasonChart" :height="`${Math.max(o.reasons.length * 38 + 12, 120)}px`" />
        </div>

        <div class="card card-pad">
          <h2 class="h-card">무엇이 판정을 결정했나</h2>
          <p class="mt-0.5 text-[12.5px] text-muted">300개 각각을 결정한 신호별 개수입니다. 하나라도 강하면 단독으로 경고가 됩니다.</p>
          <ul class="mt-4 space-y-4">
            <li v-for="d in decisionRows" :key="d.key">
              <div class="flex items-baseline justify-between gap-3">
                <span class="text-[13.5px] font-semibold">{{ d.label }}</span>
                <span class="num text-[13px] font-semibold">{{ d.count }}</span>
              </div>
              <div class="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-3">
                <div class="h-full rounded-full bg-accent transition-[width] duration-700" :style="{ width: `${Math.max(d.width, d.count ? 2 : 0)}%` }" />
              </div>
              <div class="mt-1 text-[12px] text-muted">{{ d.detail }}</div>
            </li>
          </ul>
        </div>
      </section>

      <section class="mt-4 grid gap-4 lg:grid-cols-2">
        <div class="card overflow-hidden">
          <div class="flex items-center justify-between px-5 pt-5 pb-3">
            <h2 class="h-card">우선 확인할 대상</h2>
            <RouterLink to="/identities" class="inline-flex items-center gap-1 text-[12.5px] font-semibold text-accent">전체 보기<Icon name="right" :size="14" /></RouterLink>
          </div>
          <ul>
            <li v-for="r in o.top_risk" :key="r.name" class="border-t border-line">
              <RouterLink :to="`/identities/${r.name}`" class="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-surface-2">
                <span class="num w-6 text-[12.5px] text-faint">{{ r.rank }}</span>
                <span class="min-w-0 flex-1">
                  <span class="block truncate text-[13.5px] font-semibold">{{ r.name }}</span>
                  <CloudBadge :cloud="r.cloud" />
                </span>
                <ScoreBar :value="r.risk_score" :verdict="r.verdict" :width="64" />
                <VerdictBadge :verdict="r.verdict" />
              </RouterLink>
            </li>
          </ul>
        </div>

        <div v-if="remediation" class="card card-pad">
          <h2 class="h-card">개선 시뮬레이션</h2>
          <p class="mt-0.5 text-[12.5px] text-muted">권고한 조치를 적용했다고 가정하고 다시 분석한 결과입니다. 실제 권한은 바뀌지 않아요.</p>

          <div class="mt-4 grid grid-cols-3 gap-3">
            <div class="rounded-xl bg-surface-2 p-3.5">
              <div class="eyebrow">권고 대상</div>
              <div class="num mt-1 text-2xl font-bold">{{ remediation.planned }}</div>
            </div>
            <div class="rounded-xl bg-surface-2 p-3.5">
              <div class="eyebrow">평균 위험도</div>
              <div class="num mt-1 text-[15px] leading-8 font-bold">
                {{ score(remediation.avg_before, 2) }}<span class="mx-1 text-faint">→</span><span style="color: var(--allow)">{{ score(remediation.avg_after, 2) }}</span>
              </div>
            </div>
            <div class="rounded-xl bg-surface-2 p-3.5">
              <div class="eyebrow">판정 바뀜</div>
              <div class="num mt-1 text-2xl font-bold">{{ remediation.action_changed }}<span class="ml-1 text-sm font-medium text-muted">/ {{ remediation.applied }}</span></div>
            </div>
          </div>

          <BaseChart :option="afterChart" height="104px" class="mt-3" />

          <div class="mt-2 flex flex-wrap gap-2">
            <span v-for="(n, type) in remediation.by_type" :key="type" class="chip">{{ remediationMeta[type] ?? type }} <b class="num text-ink">{{ n }}</b></span>
          </div>

          <template v-if="topFixes.length">
            <h3 class="eyebrow mt-5 mb-1">위험도가 가장 크게 줄어드는 대상</h3>
            <ul>
              <li v-for="f in topFixes" :key="f.identity" class="border-t border-line first:border-t-0">
                <RouterLink :to="`/identities/${f.identity}`" class="flex items-center gap-3 rounded-lg py-2.5 transition-colors hover:bg-surface-2">
                  <span class="min-w-0 flex-1 truncate text-[13.5px] font-semibold">{{ f.identity }}</span>
                  <span class="flex items-center gap-1.5">
                    <VerdictBadge :verdict="f.effect!.before_action" />
                    <Icon name="arrow" :size="12" class="text-faint" />
                    <VerdictBadge :verdict="f.effect!.after_action" />
                  </span>
                  <span class="num w-14 text-right text-[13px] font-semibold" style="color: var(--allow)">−{{ f.effect!.risk_reduction.toFixed(2) }}</span>
                </RouterLink>
              </li>
            </ul>
          </template>
        </div>
      </section>

      <section class="mt-4 grid gap-4 lg:grid-cols-5">
        <div class="card overflow-hidden lg:col-span-3">
          <div class="flex items-center gap-2 px-5 pt-5 pb-3">
            <Icon name="history" :size="17" class="text-muted" />
            <h2 class="h-card">저장된 분석 이력</h2>
          </div>
          <DataTable :columns="runColumns" :rows="store.runs" :row-key="(r) => String(r.run_id)" :page-size="5" empty-text="저장된 이력이 없습니다.">
            <template #cell-run_id="{ row }"><span class="num font-semibold">#{{ (row as RunRecord).run_id }}</span></template>
            <template #cell-created_at="{ row }"><span class="num">{{ kst((row as RunRecord).created_at) }}</span></template>
          </DataTable>
        </div>

        <div class="card card-pad lg:col-span-2">
          <h2 class="h-card">분석 전제와 한계</h2>
          <ul class="mt-3 space-y-2.5 text-[12.5px] leading-relaxed text-muted">
            <li v-for="(n, i) in o.notes" :key="i" class="flex gap-2.5">
              <span class="mt-2 size-1 shrink-0 rounded-full bg-faint" />{{ n }}
            </li>
          </ul>
        </div>
      </section>
    </template>
  </LoadState>
  </div>
</template>
